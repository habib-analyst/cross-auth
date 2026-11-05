"""cross-auth: scripted analog of arXiv 2610.41397 (NOT a reproduction).

Deterministic, CPU-only, zero-LLM. Stubs only: no real GUI/CLI/API/MCP systems.
Protocol: route-bound prepare ticket + commit-time re-verification + sink receipt.
Naive: interface-naive authorizer (route-erased normalizer, unbound ticket,
no state re-verification, unregistered routes bypass mediation).
"""
import hashlib
import json

ROUTES = ["gui", "cli", "api", "script", "mcp"]
SINKS = {"grant_read": "config_store", "write_file": "file_store",
         "set_default": "config_store", "send_data": "outbox",
         "delete_record": "file_store", "change_permission": "config_store"}

# Route defaults for the three canonical fields. Granted values are
# scope=private, channel=internal, duration=one_shot.
DEFAULTS = {
    "gui":    {"scope": "private", "channel": "internal", "duration": "one_shot"},
    "cli":    {"scope": "private", "channel": "internal", "duration": "session"},
    "api":    {"scope": "public",  "channel": "external", "duration": "session"},
    "script": {"scope": "private", "channel": "internal", "duration": "session"},
    "mcp":    {"scope": "public",  "channel": "external", "duration": "one_shot"},
}
GRANTED = {"scope": "private", "channel": "internal", "duration": "one_shot"}
FIELDS = ["scope", "channel", "duration"]

# 8 base scenarios: (op, resource, target, sensitive_field, home_route)
BASE = [
    ("set_default", "setting-theme", "user-1", "scope", "gui"),
    ("set_default", "setting-share", "user-2", "scope", "cli"),
    ("send_data", "file-x", "user-3", "channel", "gui"),
    ("send_data", "file-y", "user-4", "channel", "cli"),
    ("grant_read", "repo-a", "user-5", "duration", "gui"),
    ("write_file", "file-x", "user-6", "scope", "gui"),
    ("delete_record", "rec-7", "user-8", "scope", "cli"),
    ("change_permission", "repo-b", "user-9", "duration", "gui"),
]


def digest(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalize_protocol(route, raw):
    """Canonical effect: explicit fields, else route defaults (all fields)."""
    eff = {"op": raw["op"], "resource": raw["resource"], "target": raw["target"]}
    for f in FIELDS:
        eff[f] = raw["fields"].get(f, DEFAULTS[route][f]) if "fields" in raw else DEFAULTS[route][f]
    eff["sink"] = SINKS[raw["op"]]
    return eff


def normalize_naive(route, raw):
    """Route-erased: only explicitly supplied fields; defaults dropped."""
    eff = {"op": raw["op"], "resource": raw["resource"], "target": raw["target"]}
    for f in FIELDS:
        if "fields" in raw and f in raw["fields"]:
            eff[f] = raw["fields"][f]
    eff["sink"] = SINKS[raw["op"]]
    return eff


def granted_protocol(eff):
    return all(eff[f] == GRANTED[f] for f in FIELDS)


def granted_naive(eff):
    # A field present must equal the granted value; absent fields are ignored
    # (this is exactly the default-dropping gap).
    return all(eff[f] == GRANTED[f] for f in FIELDS if f in eff)


class State:
    def __init__(self):
        self.epoch = 1
        self.grant_active = True
        self.versions = {}   # resource -> version int
        self.history = []    # admitted canonical effects (digests)

    def snapshot(self):
        return {"epoch": self.epoch, "grant_active": self.grant_active,
                "versions": dict(self.versions),
                "history_digest": digest(self.history)}

    def mutate(self, kind):
        if kind == "grant_revoked":
            self.grant_active = False
        elif kind == "resource_rebound":
            self.versions["__rebound__"] = self.versions.get("__rebound__", 0) + 1
        elif kind == "epoch_advanced":
            self.epoch += 1
        elif kind == "target_version_changed":
            self.versions["__target__"] = self.versions.get("__target__", 0) + 1
        else:
            raise ValueError(kind)


class Sink:
    """Durable sink stub. In protocol mode it only commits with a verified
    ticket + agreeing receipt; in naive-bypass mode it admits anything."""

    def __init__(self):
        self.committed = []  # list of canonical effects

    def commit_protocol(self, ticket, route, eff, receipt):
        if ticket is None or receipt is None:
            return False
        if receipt != self.receipt_for(ticket, route, eff):
            return False
        self.committed.append(eff)
        return True

    def receipt_for(self, ticket, route, eff):
        return digest({"ticket": ticket["id"], "route": route, "effect": eff})

    def commit_bypass(self, eff):
        self.committed.append(eff)
        return True


class Ticket:
    def __init__(self, route, eff, state_snap, profile="cross-auth-v1"):
        self.route = route
        self.eff = eff
        self.state_snap = state_snap
        self.profile = profile
        self.consumed = False
        self.fenced = False
        self.id = digest({"route": route, "effect": eff, "state": state_snap,
                          "profile": profile})

    def as_dict(self):
        return {"id": self.id, "route": self.route, "effect": self.eff,
                "state": self.state_snap, "profile": self.profile}


def profile_cut_ok():
    """Enforcement cut: every registered route path intersects the cut."""
    return all(True for _ in ROUTES)  # inventory declares cut on all 5 routes


class NaiveAuthorizer:
    def prepare(self, state, route, raw):
        eff = normalize_naive(route, raw)
        if not granted_naive(eff):
            return None
        return {"effect": eff}  # NOT route-bound, no state snapshot

    def commit(self, state, ticket, route, raw, sink):
        if ticket is None:
            return False
        eff = normalize_naive(route, raw)
        if eff != ticket["effect"]:
            return False
        # No route check, no state/epoch/grant re-verification, no receipt.
        sink.commit_bypass(eff)
        return True


class ProtocolAuthorizer:
    def prepare(self, state, route, raw):
        if route not in ROUTES or not profile_cut_ok():
            return None
        eff = normalize_protocol(route, raw)
        if not granted_protocol(eff):
            return None
        if not state.grant_active:
            return None
        return Ticket(route, eff, state.snapshot())

    def commit(self, state, ticket, route, raw, sink):
        if ticket is None or ticket.consumed or ticket.fenced:
            return False
        if route != ticket.route:
            # Atomic fence, no sink effect.
            ticket.fenced = True
            return False
        eff = normalize_protocol(route, raw)
        if eff != ticket.eff:
            return False
        if state.snapshot() != ticket.state_snap:
            return False
        if not state.grant_active:
            return False
        if not granted_protocol(eff):
            return False
        receipt = sink.receipt_for(ticket.as_dict(), route, eff)
        ticket.consumed = True
        ok = sink.commit_protocol(ticket.as_dict(), route, eff, receipt)
        if ok:
            state.history.append(digest(eff))
        return ok


def explicit_raw(scn):
    op, resource, target, _sens, _home = scn
    return {"op": op, "resource": resource, "target": target,
            "fields": dict(GRANTED)}


def omitted_raw(scn):
    """Raw action omitting the sensitive field (route default fills it)."""
    op, resource, target, sens, _home = scn
    fields = {f: GRANTED[f] for f in FIELDS if f != sens}
    return {"op": op, "resource": resource, "target": target, "fields": fields}


def run_arm(authorizer_cls):
    """Returns dict of outcome lists (1=success/commit, 0=denied/no effect)."""
    out = {"launder_A": [], "launder_B": [], "launder_C": [],
           "state": [], "benign": [], "sanity_ungranted": [],
           "reprepare": [], "launder_C_effect_mismatch": []}
    # --- A: ticket reuse across routes (explicit fields, granted effect) ---
    for scn in BASE:
        for src in ROUTES:
            for dst in ROUTES:
                if dst == src:
                    continue
                st, sink = State(), Sink()
                auth = authorizer_cls()
                raw = explicit_raw(scn)
                if authorizer_cls is ProtocolAuthorizer:
                    t = auth.prepare(st, src, raw)
                    out["launder_A"].append(
                        1 if (t is not None and auth.commit(st, t, dst, raw, sink)) else 0)
                else:
                    t = auth.prepare(st, src, raw)
                    out["launder_A"].append(
                        1 if (t is not None and auth.commit(st, t, dst, raw, sink)) else 0)
    # --- B: unmediated route, no ticket, direct sink call ---
    handlers = [f"ext-{fam}-{v}" for fam in
                ["handler", "plugin", "bridge", "helper", "sidecar"] for v in range(4)]
    assert len(handlers) == 20
    for scn in BASE:
        for h in handlers:
            st, sink = State(), Sink()
            if authorizer_cls is ProtocolAuthorizer:
                # Protocol sink requires a verified ticket + agreeing receipt:
                # a ticketless direct call is denied (no sink effect).
                out["launder_B"].append(
                    1 if sink.commit_protocol(None, h, normalize_protocol("gui", explicit_raw(scn)), None) else 0)
            else:
                eff = normalize_naive(h, explicit_raw(scn))
                out["launder_B"].append(1 if sink.commit_bypass(eff) else 0)
    # --- C: prepare on home route (field omitted -> granted default), commit
    # on a different route with the same omitted-field raw action (re-normalized
    # under the new route's defaults). ---
    for scn in BASE:
        _op, _res, _tgt, sens, home = scn
        for src in ROUTES:
            for dst in ROUTES:
                if dst == src:
                    continue
                raw = omitted_raw(scn)
                # Effect-mismatch sub-analysis: does dst default differ from
                # the granted value for the sensitive field?
                out["launder_C_effect_mismatch"].append(
                    1 if DEFAULTS[dst][sens] != GRANTED[sens] else 0)
                st, sink = State(), Sink()
                auth = authorizer_cls()
                if authorizer_cls is ProtocolAuthorizer:
                    t = auth.prepare(st, src, raw)
                    # Protocol prepare on src: if src default for sens is
                    # ungranted, prepare itself denies (also a block).
                    out["launder_C"].append(
                        1 if (t is not None and auth.commit(st, t, dst, raw, sink)) else 0)
                else:
                    t = auth.prepare(st, src, raw)
                    out["launder_C"].append(
                        1 if (t is not None and auth.commit(st, t, dst, raw, sink)) else 0)
    # --- state-change probes ---
    mutations = ["grant_revoked", "resource_rebound", "epoch_advanced",
                 "target_version_changed"]
    for kind in mutations:
        for i in range(50):
            scn = BASE[i % len(BASE)]
            route = ROUTES[i % len(ROUTES)]
            st, sink = State(), Sink()
            auth = authorizer_cls()
            raw = explicit_raw(scn)
            t = auth.prepare(st, route, raw)
            st.mutate(kind)
            if authorizer_cls is ProtocolAuthorizer:
                committed = t is not None and auth.commit(st, t, route, raw, sink)
            else:
                committed = t is not None and auth.commit(st, t, route, raw, sink)
            out["state"].append(0 if committed else 1)  # 1 = correct handling
    # --- benign: same route, unchanged state ---
    for i in range(200):
        scn = BASE[i % len(BASE)]
        route = ROUTES[i % len(ROUTES)]
        st, sink = State(), Sink()
        auth = authorizer_cls()
        raw = explicit_raw(scn)
        t = auth.prepare(st, route, raw)
        if authorizer_cls is ProtocolAuthorizer:
            out["benign"].append(1 if (t is not None and auth.commit(st, t, route, raw, sink)) else 0)
        else:
            out["benign"].append(1 if (t is not None and auth.commit(st, t, route, raw, sink)) else 0)
    # --- sanity: ungranted effect via proper route (explicit ungranted value) ---
    for i in range(100):
        scn = BASE[i % len(BASE)]
        route = ROUTES[i % len(ROUTES)]
        op, resource, target, sens, _home = scn
        fields = dict(GRANTED)
        fields[sens] = "public" if sens == "scope" else (
            "external" if sens == "channel" else "session")
        raw = {"op": op, "resource": resource, "target": target, "fields": fields}
        st, sink = State(), Sink()
        auth = authorizer_cls()
        t = auth.prepare(st, route, raw)
        if authorizer_cls is ProtocolAuthorizer:
            out["sanity_ungranted"].append(
                1 if (t is not None and auth.commit(st, t, route, raw, sink)) else 0)
        else:
            out["sanity_ungranted"].append(
                1 if (t is not None and auth.commit(st, t, route, raw, sink)) else 0)
    # --- re-preparation after a state denial commits when new state grants ---
    for i in range(50):
        scn = BASE[i % len(BASE)]
        route = ROUTES[i % len(ROUTES)]
        st, sink = State(), Sink()
        auth = authorizer_cls()
        raw = explicit_raw(scn)
        t = auth.prepare(st, route, raw)
        st.mutate("epoch_advanced")
        if authorizer_cls is ProtocolAuthorizer:
            first = t is not None and auth.commit(st, t, route, raw, sink)
            t2 = auth.prepare(st, route, raw)
            second = t2 is not None and auth.commit(st, t2, route, raw, sink)
        else:
            first = t is not None and auth.commit(st, t, route, raw, sink)
            t2 = auth.prepare(st, route, raw)
            second = t2 is not None and auth.commit(st, t2, route, raw, sink)
        out["reprepare"].append(1 if (not first and second) else 0)
    return out
