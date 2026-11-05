# cross-auth

Scripted analog of cross-interface authorization for AI computer-use agents
(analog of arXiv 2610.41397 — **not** a reproduction of that paper, and none
of its figures are claimed as reproduced).

The disease: a policy decision can be interface-invariant while its
executable authorization is not — another route (GUI vs CLI vs API vs
script vs MCP) can bypass mediation, alter a security-relevant default, or
commit after the authorized state changed.

The protocol: a fixed, versioned profile enumerating effect-bearing routes
and durable sinks, a route-to-sink enforcement cut, normalization of each
request to a canonical effect, a route-bound prepare ticket, re-verification
of route / effect / grant / trace / profile / inventory / state at commit,
and an agreeing sink receipt.

## Measured results (seed 20261102, deterministic, stdlib only)

- Naive authorizer succeeds on 480/480 scripted laundering attempts.
- Route-bound protocol blocks 480/480, handles 200/200 commit-time
  state-change probes correctly (deny, no sink effect), and lets 200/200
  benign commits succeed.
- 15/15 unit tests green; seed rerun produces a byte-identical
  `results.json`.

See `PREREG.md` for the locked bars and decision rule, and
`hidden_files/papers/cross-auth/PAPER.md` in the goal workspace (not in
this repo) for the full writeup — or the summary in this README's
provenance note: scripted stubs only, no real GUI/CLI/API/MCP systems,
no LLM agents. Profile-boundedness is the point and the limit.

## Run

```
python3 -m unittest discover -s tests -v
python3 run_experiment.py   # writes results.json
```

## Layout

- `src/cross_auth.py` — naive + protocol authorizers, sinks, scenario generation
- `run_experiment.py` — experiment + paired bootstrap CIs (B=2000)
- `tests/` — unit tests
- `PREREG.md` — pre-registered bars (written before any headline number)
- `results.json` — measured results
