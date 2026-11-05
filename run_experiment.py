"""Run the cross-auth experiment, compute paired bootstrap CIs, write results.json.

No timestamps, no randomness except the seeded bootstrap (seed 20261102).
Rerunning with the same seed must produce a byte-identical results.json.
"""
import json
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from cross_auth import NaiveAuthorizer, ProtocolAuthorizer, run_arm

SEED = 20261102
B = 2000


def wilson(x, n):
    if n == 0:
        return [0.0, 0.0]
    p = x / n
    z = 1.959964
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [max(0.0, (c - m) / d), min(1.0, (c + m) / d)]


def boot_paired(a, b, seed=SEED):
    """Paired bootstrap CI for mean(a) - mean(b); a, b same-length 0/1 lists."""
    rng = random.Random(seed)
    n = len(a)
    diffs = []
    for _ in range(B):
        idx = [rng.randrange(n) for _ in range(n)]
        diffs.append(sum(a[i] for i in idx) / n - sum(b[i] for i in idx) / n)
    diffs.sort()
    lo = diffs[int(0.025 * B)]
    hi = diffs[int(0.975 * B) - 1]
    return [lo, hi]


def boot_single(a, seed=SEED):
    rng = random.Random(seed + 1)
    n = len(a)
    vals = []
    for _ in range(B):
        idx = [rng.randrange(n) for _ in range(n)]
        vals.append(sum(a[i] for i in idx) / n)
    vals.sort()
    return [vals[int(0.025 * B)], vals[int(0.975 * B) - 1]]


def rate(lst):
    return {"x": int(sum(lst)), "n": len(lst),
            "rate": (sum(lst) / len(lst)) if lst else 0.0}


def main():
    naive = run_arm(NaiveAuthorizer)
    proto = run_arm(ProtocolAuthorizer)
    # Per-attempt laundering lists are parallel across arms by construction:
    # A (160) + B (160) + C (160), concatenated in that order.
    naive_launder = naive["launder_A"] + naive["launder_B"] + naive["launder_C"]
    proto_launder = proto["launder_A"] + proto["launder_B"] + proto["launder_C"]
    naive_block = [1 - v for v in naive_launder]
    proto_block = [1 - v for v in proto_launder]
    res = {
        "seed": SEED,
        "bootstrap_B": B,
        "g2_naive_launder_success": rate(naive_launder),
        "g2_naive_launder_success_wilson95": wilson(sum(naive_launder), len(naive_launder)),
        "g2_naive_launder_success_boot95": boot_single(naive_launder),
        "g2_by_type_naive": {
            "A_ticket_reuse": rate(naive["launder_A"]),
            "B_unmediated": rate(naive["launder_B"]),
            "C_default_altered": rate(naive["launder_C"]),
        },
        "g3a_proto_launder_block": rate(proto_block),
        "g3a_proto_launder_block_wilson95": wilson(sum(proto_block), len(proto_block)),
        "g3a_proto_launder_block_boot95": boot_single(proto_block),
        "g3a_paired_diff_block_proto_minus_naive": {
            "diff": sum(proto_block) / len(proto_block) - sum(naive_block) / len(naive_block),
            "boot95": boot_paired(proto_block, naive_block),
        },
        "g3a_by_type_proto_block": {
            "A_ticket_reuse": rate([1 - v for v in proto["launder_A"]]),
            "B_unmediated": rate([1 - v for v in proto["launder_B"]]),
            "C_default_altered": rate([1 - v for v in proto["launder_C"]]),
        },
        "launder_C_effect_mismatch_fraction": rate(proto["launder_C_effect_mismatch"]),
        "g3b_proto_state_correct": rate(proto["state"]),
        "g3b_proto_state_correct_wilson95": wilson(sum(proto["state"]), len(proto["state"])),
        "g3b_naive_state_correct": rate(naive["state"]),
        "g3b_paired_diff_correct_proto_minus_naive": {
            "diff": sum(proto["state"]) / len(proto["state"]) - sum(naive["state"]) / len(naive["state"]),
            "boot95": boot_paired(proto["state"], naive["state"]),
        },
        "g3c_proto_benign_success": rate(proto["benign"]),
        "g3c_proto_benign_success_wilson95": wilson(sum(proto["benign"]), len(proto["benign"])),
        "g3c_proto_benign_success_boot95": boot_single(proto["benign"]),
        "g3c_naive_benign_success": rate(naive["benign"]),
        "sanity_ungranted_committed_proto": rate(proto["sanity_ungranted"]),
        "sanity_ungranted_committed_naive": rate(naive["sanity_ungranted"]),
        "reprepare_after_denial_proto": rate(proto["reprepare"]),
        "reprepare_after_denial_naive": rate(naive["reprepare"]),
        "counts": {
            "launder_total": len(naive_launder),
            "state_probes": len(proto["state"]),
            "benign": len(proto["benign"]),
            "sanity": len(proto["sanity_ungranted"]),
            "reprepare": len(proto["reprepare"]),
        },
    }
    out = Path(__file__).resolve().parent / "results.json"
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(json.dumps(res, indent=2, sort_keys=True))
    # Gate verdicts (locked bars from PREREG.md)
    g2 = res["g2_naive_launder_success"]["rate"] >= 0.50 and res["g2_naive_launder_success_boot95"][0] > 0
    g3a = res["g3a_proto_launder_block"]["rate"] >= 0.95 and res["g3a_paired_diff_block_proto_minus_naive"]["boot95"][0] > 0
    g3b = res["g3b_proto_state_correct"]["rate"] >= 0.95 and res["g3b_paired_diff_correct_proto_minus_naive"]["boot95"][0] > 0
    g3c = res["g3c_proto_benign_success"]["rate"] >= 0.95
    print(f"GATES: G2={g2} G3a={g3a} G3b={g3b} G3c={g3c}")
    return 0 if (g2 and g3a and g3b and g3c) else 1


if __name__ == "__main__":
    raise SystemExit(main())
