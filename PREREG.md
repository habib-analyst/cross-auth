# PREREG — cross-auth (foundry #124)

**Paper (analog source, NOT claimed as reproduced):** arXiv 2610.41397,
"Cross-Interface Authorization for AI Computer-Use Agents" (Genliang Zhu, Chu Wang,
submitted 30 Oct 2026). Paper figures are context only and are NEVER presented as
reproduced: 3,464 traces / 1,732 scenarios; checker accepts all retained traces,
rejects 26/26 semantic regressions; 24/24 and 720/720 mutant suites rejected;
168/168 commit probes match.

**Analog claim (scripted only):** a policy decision can be interface-invariant
while its executable authorization is not. A route-bound prepare/commit protocol
over a fixed, versioned profile — enumerate effect-bearing routes and durable
sinks, check a route-to-sink enforcement cut, normalize each request to a
canonical effect, issue a route-bound prepare ticket, re-verify
route/effect/grant/trace/profile/inventory/state at commit, require an agreeing
sink receipt — blocks alternate-route laundering and stale-state commits without
blanket-denying legitimate commits.

**Seed:** 20261102. No LLM, no network, no wall-clock in results. Deterministic
generation: all scenario lists are fixed combinatorial loops in seed order;
`results.json` is written with sorted keys and no timestamps, so a seed rerun
must be byte-identical (G0 determinism check).

## G1 — live author-code recheck (done BEFORE any headline number, 2026-11-02)
- arXiv abs page (2610.41397): no code link, no code/data/media section.
- Full-text HTML scan (arXiv html/2610.41397v1, 3,550 lines): `github` hits are
  ONLY third-party references (microsoft/magentic-ui, VancouverCanada/openport,
  weavebench/WeaveBench); `accentrust` hits are ONLY author affiliations/emails;
  no "Code Availability" section; no author repository named in any figure
  caption (Figure 1: enforcement path; Figure 2: route switch).
- Explicit author statement, "Data, Code, and Materials Availability": "The Paper 12
  reference implementation … [is] retained privately and [is] not distributed with
  this preprint. No public code, data, trace, report, or artifact URL is claimed."
  OpenPort / audited upstream repos are stated NOT to make the Paper 12 artifact
  public.
- Web/GitHub searches for the title, authors, and "accentrust" returned no author
  repo for THIS paper (OpenPort is a different paper by the same authors).
- **G1 verdict: PASS — no author code exists for 2610.41397. Build proceeds.**
  (If any of the above had found author code, the build would STAND DOWN.)

## Differentiation (binding)
- **AuthorizationBench (2610.27548): DEAD by author code.** This build does not
  touch approval correctness and does not reuse that benchmark.
- **#72 corrmonitor: KILLED at G2.** That was authorization alignment; this build
  is NOT alignment and NOT approver accuracy.
- **This paper's mechanism is different:** cross-interface route laundering +
  commit-time re-verification. There is NO approver (human or LLM) anywhere in
  this design, no approval-correctness metric, and no "did the approver decide
  correctly" score. If the analog degenerates into approver accuracy, KILL.
  Metric objects are tickets, routes, canonical effects, grants, state versions,
  trace prefixes, and sink receipts — never approval judgments.

## Arms
- **Naive authorizer (interface-naive):** policy is evaluated on a
  route-erased normalizer (route defaults dropped from the canonical effect);
  prepare issues a ticket bound only to the (erased) effect, NOT to a route;
  commit re-checks only the erased effect against the grant set — no route
  check, no state/epoch/grant re-verification, no trace-prefix check, no sink
  receipt requirement; any request arriving via an unregistered route bypasses
  the authorizer entirely and is admitted by the sink.
- **Protocol authorizer (route-bound):** profile-bounded protocol. Prepare
  normalizes with route defaults included in the canonical effect, checks the
  route-to-sink enforcement cut (every registered route path intersects the
  cut; unregistered routes get no ticket), evaluates policy on the canonical
  effect plus trace closure, snapshots authoritative state (grant body, epoch,
  resource binding, version), and issues a ticket bound to actor/task/request/
  exact route/sink/canonical effect/grant/profile+inventory digests/state
  witness/trace-prefix digest. Commit re-resolves and re-normalizes, verifies
  route equality, effect equality, grant still valid and identical, state
  witness unchanged, trace prefix unchanged, ticket unconsumed, and requires an
  agreeing sink receipt; a route mismatch atomically fences the old ticket
  with NO sink effect. A denied ticket can be re-prepared fresh (new ticket,
  new state snapshot) and then commit — re-preparation is counted separately,
  never as a pass of the stale ticket.

## Scripted environment (stubs, not real apps)
- Interfaces/routes: GUI, CLI, API, script, MCP (5 registered routes per effect
  family, plus unregistered handler routes that bypass mediation in the naive arm).
- Durable sinks: config_store, file_store, outbox (3 sinks).
- Effect families (6): grant_read, write_file, set_default, send_data,
  delete_record, change_permission. Each family has 8 base instantiations
  (resource × target combinations), fixed in code.
- Route defaults that matter (examples, full table in code): for `set_default`,
  GUI defaults scope=private while API defaults scope=public; for `send_data`,
  CLI defaults channel=internal while MCP defaults channel=external; for
  `grant_read`, script defaults duration=session while GUI defaults
  duration=one_shot. The naive normalizer drops these fields; the protocol
  normalizer includes them, so a default-altered request is a DIFFERENT
  canonical effect under the protocol.
- Grants: a fixed grant set over PROTOCOL canonical effects. A benign effect is
  one whose protocol canonical effect is granted; a default-altered effect whose
  protocol canonical effect is NOT granted is unauthorized even when its naive
  (erased) canonical effect IS granted.

## Pre-registered bars (locked BEFORE any headline number is generated)
Decision rule: **ANY locked bar fails → KILL. No bar-moving after this file.**

- **G0:** unit tests all green AND seed rerun of the experiment produces a
  byte-identical `results.json` (sha256 match). Fail → KILL.
- **G2 (disease):** naive authorizer succeeds on ≥50% of laundering attempts,
  with the 95% paired-bootstrap CI lower bound excluding 0.
  Laundering attempts (denominator, fixed before running):
  - (A) ticket reuse across routes: prepare on one registered route, commit the
    SAME ticket on a different registered route, same raw action (granted effect).
    n = 160 (8 instantiations × 5 source routes × 4 different target routes).
  - (B) unmediated alternate route: direct sink commit via an unregistered
    handler route with NO ticket (granted effect). n = 160 (8 × 5 × 4 handler
    variants).
  - (C) default-altered effect: prepare/commit via a route whose default makes
    the protocol canonical effect UNGRANTED, while the naive erased effect IS
    granted. n = 160 (8 default-sensitive instantiations × 20 route pairs).
  - Total laundering n = 480. "Succeeds" = sink effect committed.
- **G3a (load-bearing, blocking):** protocol blocks ≥95% of the SAME 480
  laundering attempts, with the 95% paired-bootstrap CI lower bound excluding
  the naive success rate's complement — concretely, the CI for
  (protocol block rate − naive block rate) excludes 0, and the protocol block
  rate point estimate ≥ 0.95. "Blocks" = no sink effect committed.
- **G3b (load-bearing, commit-time state safety):** protocol correctly handles
  ≥95% of commit-time state-change probes (95% bootstrap CI lower bound ≥ 0.90
  is reported; the locked bar is the point estimate ≥ 0.95 with CI excluding
  the naive correct-handling rate). Probes n = 200 (4 mutation types × 50:
  grant revoked; resource rebound; policy epoch advanced; target version
  changed — each applied between prepare and commit of an otherwise-benign
  ticket). "Correct" = commit DENIED with NO sink effect (re-preparation after
  the change is a separate, uncounted step). Naive correct-handling is measured
  on the same 200 probes for the paired comparison.
- **G3c (load-bearing, no blanket deny):** protocol succeeds on ≥95% of benign
  commits (95% bootstrap CI lower bound ≥ 0.90 reported; locked bar is point
  estimate ≥ 0.95). Benign n = 200: prepare and commit on the SAME registered
  route, unchanged state, agreeing sink receipt.
- **Sanity (not a gate, reported):** ungranted effects via a proper route are
  denied by BOTH arms (n = 100); re-preparation after a state-change denial
  yields a fresh ticket that commits when the new state grants it (n = 50,
  reported only).

## Metrics and statistics
- Primary metrics are proportions with counts (x/n) for each arm × probe set.
- 95% CIs: paired bootstrap over attempts (resample attempts with replacement,
  B = 2000, seed 20261102), percentile intervals, computed on the SAME attempt
  index sets for both arms so the paired difference CI is valid. Wilson
  intervals are also reported for single proportions. With deterministic arms,
  degenerate intervals (e.g. [1.0, 1.0]) are reported as-is, not smoothed.
- No p-hacking: denominators, arms, and bars above are fixed here; no
  post-hoc subgroup is allowed to rescue a failed bar.

## Scope limits (to appear verbatim in spirit in PAPER.md)
Scripted analog only. Stubs, not real GUI/CLI/API/MCP systems; no real
applications, no real users, no LLM agents. Results demonstrate that the
route-binding + commit re-verification mechanism closes the three scripted
laundering gaps without blanket-denying scripted benign commits. They do NOT
reproduce the paper's 3,464-trace evaluation, do NOT claim the paper's theorems,
and do NOT generalize to unregistered real-world routes outside the fixed
profile — profile-boundedness is the point and the limit.
