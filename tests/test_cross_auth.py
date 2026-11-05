"""Unit tests for cross-auth (G0). Pure stdlib, deterministic."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from cross_auth import (DEFAULTS, ROUTES, NaiveAuthorizer, ProtocolAuthorizer,
                        Sink, State, explicit_raw, normalize_naive,
                        normalize_protocol, omitted_raw, profile_cut_ok, BASE)


def fresh(auth_cls):
    return State(), Sink(), auth_cls()


class TestCrossAuth(unittest.TestCase):
    def test_cut_covers_all_routes(self):
        self.assertTrue(profile_cut_ok())
        self.assertEqual(len(ROUTES), 5)

    def test_protocol_normalizer_includes_defaults(self):
        scn = BASE[0]  # set_default, sensitive scope
        eff_gui = normalize_protocol("gui", omitted_raw(scn))
        eff_api = normalize_protocol("api", omitted_raw(scn))
        self.assertEqual(eff_gui["scope"], "private")
        self.assertEqual(eff_api["scope"], "public")
        self.assertNotEqual(eff_gui, eff_api)

    def test_naive_normalizer_drops_defaults(self):
        scn = BASE[0]
        self.assertNotIn("scope", normalize_naive("api", omitted_raw(scn)))
        self.assertEqual(normalize_naive("gui", omitted_raw(scn)),
                         normalize_naive("api", omitted_raw(scn)))

    def test_explicit_effect_identical_across_routes_protocol(self):
        scn = BASE[0]
        self.assertEqual(normalize_protocol("gui", explicit_raw(scn)),
                         normalize_protocol("api", explicit_raw(scn)))

    def test_benign_protocol_commit(self):
        st, sink, auth = fresh(ProtocolAuthorizer)
        raw = explicit_raw(BASE[0])
        t = auth.prepare(st, "gui", raw)
        self.assertIsNotNone(t)
        self.assertTrue(auth.commit(st, t, "gui", raw, sink))
        self.assertEqual(len(sink.committed), 1)

    def test_ticket_reuse_fenced_no_sink_effect(self):
        st, sink, auth = fresh(ProtocolAuthorizer)
        raw = explicit_raw(BASE[0])
        t = auth.prepare(st, "gui", raw)
        self.assertFalse(auth.commit(st, t, "cli", raw, sink))
        self.assertTrue(t.fenced)
        self.assertEqual(len(sink.committed), 0)
        # Fenced ticket cannot be redeemed later, even on the home route.
        self.assertFalse(auth.commit(st, t, "gui", raw, sink))

    def test_ticket_replay_consumed(self):
        st, sink, auth = fresh(ProtocolAuthorizer)
        raw = explicit_raw(BASE[0])
        t = auth.prepare(st, "gui", raw)
        self.assertTrue(auth.commit(st, t, "gui", raw, sink))
        self.assertFalse(auth.commit(st, t, "gui", raw, sink))
        self.assertEqual(len(sink.committed), 1)

    def test_state_change_denies_protocol(self):
        for kind in ["grant_revoked", "resource_rebound", "epoch_advanced",
                     "target_version_changed"]:
            st, sink, auth = fresh(ProtocolAuthorizer)
            raw = explicit_raw(BASE[1])
            t = auth.prepare(st, "cli", raw)
            st.mutate(kind)
            self.assertFalse(auth.commit(st, t, "cli", raw, sink))
            self.assertEqual(len(sink.committed), 0)

    def test_reprepare_after_state_change_commits(self):
        st, sink, auth = fresh(ProtocolAuthorizer)
        raw = explicit_raw(BASE[1])
        t = auth.prepare(st, "cli", raw)
        st.mutate("epoch_advanced")
        self.assertFalse(auth.commit(st, t, "cli", raw, sink))
        t2 = auth.prepare(st, "cli", raw)
        self.assertIsNotNone(t2)
        self.assertTrue(auth.commit(st, t2, "cli", raw, sink))

    def test_unregistered_route_gets_no_ticket(self):
        st, _sink, auth = fresh(ProtocolAuthorizer)
        self.assertIsNone(auth.prepare(st, "ext-handler-0", explicit_raw(BASE[0])))

    def test_default_altered_prepare_denied_protocol(self):
        st, _sink, auth = fresh(ProtocolAuthorizer)
        # api default scope=public is ungranted for a set_default scenario.
        self.assertIsNone(auth.prepare(st, "api", omitted_raw(BASE[0])))

    def test_naive_allows_ticket_reuse(self):
        st, sink, auth = fresh(NaiveAuthorizer)
        raw = explicit_raw(BASE[0])
        t = auth.prepare(st, "gui", raw)
        self.assertTrue(auth.commit(st, t, "cli", raw, sink))

    def test_naive_commits_after_state_change(self):
        st, sink, auth = fresh(NaiveAuthorizer)
        raw = explicit_raw(BASE[0])
        t = auth.prepare(st, "gui", raw)
        st.mutate("grant_revoked")
        self.assertTrue(auth.commit(st, t, "gui", raw, sink))

    def test_ungranted_denied_both_arms(self):
        for cls in (ProtocolAuthorizer, NaiveAuthorizer):
            st, sink, auth = fresh(cls)
            raw = {"op": "set_default", "resource": "setting-theme",
                   "target": "user-1",
                   "fields": {"scope": "public", "channel": "internal",
                              "duration": "one_shot"}}
            self.assertIsNone(auth.prepare(st, "gui", raw))

    def test_receipt_required(self):
        sink = Sink()
        self.assertFalse(sink.commit_protocol(None, "gui", {}, None))


if __name__ == "__main__":
    unittest.main()
