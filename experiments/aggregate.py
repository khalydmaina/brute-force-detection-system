"""Aggregate detection runs: mean +/- std across seeds, per-family campaign detection and delay,
Fail2Ban replayed on ground-truth authentication failures (independent of the proposed system's responses)."""
import json, glob, statistics as st, sys
from collections import defaultdict
sys.path.insert(0, "."); from eval_detection import fail2ban_replay, lockout_replay, metrics, benign_outcomes

def gt_failed(log):
    # attacks never use a valid password; in B2 every request except the last is a typo
    last_b2 = {}
    for i, e in enumerate(log):
        if e["campaign"].startswith("B2"): last_b2[e["campaign"]] = i
    for i, e in enumerate(log):
        e["failed"] = bool(e["label"]) or (e["campaign"].startswith("B2") and last_b2[e["campaign"]] != i)
    return log

def summarise(variant):
    runs = []
    for f in sorted(glob.glob(f"v{variant}_s[0-9]*.json")):
        d = json.load(open(f)); L = gt_failed(sorted(d["log"], key=lambda x: x["t"]))
        errs = sum(1 for e in L if e["tier"] == -1)
        runs.append(dict(n=len(L), errors=errs, attack=sum(e["label"] for e in L),
                         ours=metrics(L, [e["tier"] in (2, 3, 4) for e in L]),
                         f2b=metrics(L, fail2ban_replay(L)),
                         lockout=metrics(L, lockout_replay(L)), ben=benign_outcomes(L),
                         detect=[e["detect_ms"] for e in L if isinstance(e["detect_ms"], (int, float))]))
    return runs

ms = lambda xs: f"{st.mean(xs):.3f} ± {st.stdev(xs):.3f}" if len(xs) > 1 else f"{xs[0]:.3f}"
out = {}
VARIANTS = [("0", "original"), ("1", "refined"), ("2", "upgraded"), ("2b", "upgraded_benign_only")]
for v, name in VARIANTS:
    R = summarise(v)
    if not R: continue
    print(f"\n===== {name} scoring: {len(R)} seeds, requests/run={[r['n'] for r in R]}, attack/run={[r['attack'] for r in R]}, client errors={[r['errors'] for r in R]}")
    o = {}
    o["benign_outcomes"] = [r["ben"] for r in R]; print("  benign outcomes:", o["benign_outcomes"])
    for sysk in ("ours", "f2b", "lockout"):
        row = {k: ms([r[sysk][k] for r in R]) for k in ("accuracy", "precision", "recall", "fpr")}
        row.update({k: round(st.mean([r[sysk][k] for r in R]), 1) for k in ("tp", "fn", "fp", "tn")})
        fam = defaultdict(lambda: [0, 0, [], 0, 0])
        for r in R:
            for f, x in r[sysk]["families"].items():
                F = fam[f]; F[0] += x["n"]; F[1] += x["detected"]; F[2] += x["delays"]; F[3] += x["fp_requests"]; F[4] += x["requests"]
        row["families"] = {f: dict(campaigns=F[0], flagged=F[1], mean_delay=round(st.mean(F[2]), 2) if F[2] else None,
                                   fp_requests=F[3], requests=F[4]) for f, F in sorted(fam.items())}
        o[sysk] = row
        print(f"  [{sysk}] acc {row['accuracy']} | prec {row['precision']} | rec {row['recall']} | FPR {row['fpr']} | mean TP/FN/FP/TN {row['tp']}/{row['fn']}/{row['fp']}/{row['tn']}")
        for f, x in row["families"].items(): print(f"      {f:18s} {x}")
    D = sorted(x for r in R for x in r["detect"]); q = lambda p: round(D[min(len(D) - 1, int(p * len(D)))], 2)
    o["detect_ms"] = dict(n=len(D), p50=q(.5), p95=q(.95), p99=q(.99), max=round(D[-1], 2), mean=round(st.mean(D), 2))
    print("  detection overhead ms:", o["detect_ms"]); out[name] = o
json.dump(out, open("detection_summary.json", "w"), indent=1)
