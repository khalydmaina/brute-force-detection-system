"""
Detection evaluation harness (revision experiments).
Sends labeled benign and adversarial traffic to the gateway's /test/login endpoint
(simulated source IPs), records every decision, and computes:
  - per-request confusion matrix (flagged = Tier 2/3/4)
  - per-campaign detection rate and detection delay (requests before first flag)
  - the same traces replayed through Fail2Ban's per-IP counting rule
    (maxretry=5, findtime=600s), so both systems see identical traffic.
Usage: python eval_detection.py --seed 1 --out results_seed1.json
"""
import argparse, json, random, time, threading, requests
from collections import defaultdict

API = "http://localhost:8000/test/login"
USERS = [f"user{i}" for i in range(1, 41)] + ["alice", "bob", "charlie", "admin",
         "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory"]
PW = lambda u: f"Pw-{u}-2026"
LOG, LOCK = [], threading.Lock()

def send(campaign, label, ip, user, pw):
    t = time.time()
    try:
        r = requests.post(API, json={"username": user, "password": pw, "simulated_ip": ip}, timeout=30)
        d = r.json()
    except Exception as e:
        d = {"tier": -1, "status": f"error:{e}"}
    solved = None
    if label == 0 and d.get("status") == "captcha_required":
        try:   # a human solves the challenge and retries
            r2 = requests.post(API, json={"username": user, "password": pw, "simulated_ip": ip,
                                          "captcha_token": "mock-valid-token"}, timeout=30)
            solved = r2.json().get("status")
        except Exception as e:
            solved = f"error:{e}"
    with LOCK:
        LOG.append(dict(t=t, campaign=campaign, label=label, ip=ip, user=user, reason=d.get("reason"), solved=solved,
                        tier=d.get("tier"), status=d.get("status"),
                        detect_ms=d.get("detect_ms", d.get("latency_ms")),
                        latency_ms=d.get("latency_ms"),
                        failed=(d.get("status") != "success")))

def run_all(seed, benign_only=False):
    R = random.Random(seed)
    s = seed  # IP namespace per seed so runs do not share Redis state
    jobs = []
    def job(f, *a): jobs.append(threading.Thread(target=f, args=a))

    # ---------------- adversarial ----------------
    def vertical(c):          # A1: high-velocity guessing, one IP, one account
        ip = f"10.{s}.1.{c}"
        for i in range(40): send(f"A1-vertical-{c}", 1, ip, "admin", f"guess{i}"); time.sleep(0.05)
    def stuffing(c):          # A2: one IP, 10 accounts x 3 attempts
        ip = f"10.{s}.2.{c}"
        for u in R.sample(USERS, 10):
            for k in range(3): send(f"A2-stuffing-{c}", 1, ip, u, f"leak{k}"); time.sleep(0.1)
    def lowslow(c):           # A3: one IP, fixed 4s pacing, small jitter
        ip = f"10.{s}.3.{c}"
        for i in range(15): send(f"A3-lowslow-{c}", 1, ip, "bob", f"slow{i}"); time.sleep(4 + R.uniform(-0.1, 0.1))
    def honeypot(c):          # A4: decoy username
        send(f"A4-honeypot-{c}", 1, f"10.{s}.4.{c}", "admin_honeypot", "x")
    def dist_stuffing():      # A5: IP rotation, 1 attempt per IP, distinct accounts
        for i in range(200):
            send("A5-dist-stuffing", 1, f"10.{s}.{50 + i // 250}.{i % 250 + 1}", USERS[i % len(USERS)], "leak"); time.sleep(0.02)
    def dist_brute():         # A6: IP rotation against a single account
        for i in range(60):
            send("A6-dist-brute", 1, f"10.{s}.60.{i + 1}", "charlie", f"g{i}"); time.sleep(0.05)

    # B6: returning users. Warm-up (before any attack) establishes a successful login from their usual IP.
    returning = [(f"172.{s}.6.{c}", USERS[(c * 7) % len(USERS)]) for c in range(1, 21)]
    for ip, u in returning: send("B6-returning-warmup", 0, ip, u, PW(u))
    WARM_N = len(LOG)
    if not benign_only:
        for c in range(1, 6): job(vertical, c)
        for c in range(1, 6): job(stuffing, c)
        for c in range(1, 4): job(lowslow, c)
        for c in range(1, 6): job(honeypot, c)
        job(dist_stuffing); job(dist_brute)

    # ---------------- benign ----------------
    def normal(c):            # B1: correct logins, irregular human timing
        time.sleep(R.uniform(0, 45))   # spread benign sessions across the attack window
        ip, u = f"172.{s}.1.{c}", R.choice(USERS)
        for _ in range(R.randint(1, 3)): send(f"B1-normal-{c}", 0, ip, u, PW(u)); time.sleep(R.uniform(0.5, 8))
    def typo(c):              # B2: 1-3 mistypes then success
        time.sleep(R.uniform(0, 45))   # spread benign sessions across the attack window
        ip, u = f"172.{s}.2.{c}", R.choice(USERS)
        for _ in range(R.randint(1, 3)): send(f"B2-typo-{c}", 0, ip, u, PW(u) + "x"); time.sleep(R.uniform(1.5, 6))
        send(f"B2-typo-{c}", 0, ip, u, PW(u))
    def nat_office(c):        # B3: several employees behind one shared IP
        time.sleep(R.uniform(0, 45))   # spread benign sessions across the attack window
        ip = f"172.{s}.3.{c}"
        for u in R.sample(USERS, 8): send(f"B3-nat-{c}", 0, ip, u, PW(u)); time.sleep(R.uniform(1, 6))
    def pwmanager(c):         # B4: autofill, immediate single login
        time.sleep(R.uniform(0, 45))   # spread benign sessions across the attack window
        u = R.choice(USERS); send(f"B4-pwmgr-{c}", 0, f"172.{s}.4.{c}", u, PW(u))
    def shared_target(c):     # B5: user logs in from phone + laptop + office (multi-IP, same account)
        time.sleep(R.uniform(0, 45))   # spread benign sessions across the attack window
        u = USERS[c]
        for k in range(3): send(f"B5-multidevice-{c}", 0, f"172.{s}.5.{c * 3 + k}", u, PW(u)); time.sleep(R.uniform(1, 5))

    for c in range(1, 31): job(normal, c)
    for c in range(1, 21): job(typo, c)
    for c in range(1, 4): job(nat_office, c)
    for c in range(1, 11): job(pwmanager, c)
    for c in range(1, 6): job(shared_target, c)
    def returning_user(c):
        ip, u = returning[c]
        time.sleep(R.uniform(2, 40))
        for _ in range(R.randint(1, 2)): send(f"B6-returning-{c}", 0, ip, u, PW(u)); time.sleep(R.uniform(2, 10))
    for c in range(20): job(returning_user, c)

    R.shuffle(jobs)
    for j in jobs: j.start(); time.sleep(0.05)
    for j in jobs: j.join()
    del LOG[:WARM_N]   # warm-up requests are setup, not evaluation traffic

def fail2ban_replay(log, maxretry=5, findtime=600):
    """Per-IP Fail2Ban rule: ban once maxretry failures fall inside findtime."""
    fails, banned, out = defaultdict(list), set(), []
    for e in sorted(log, key=lambda x: x["t"]):
        if e["ip"] in banned: out.append(True); continue
        out.append(False)
        # Fail2Ban only sees failures from the app log; ban applies to later requests
        if e["failed"]:
            fails[e["ip"]] = [t for t in fails[e["ip"]] if e["t"] - t <= findtime] + [e["t"]]
            if len(fails[e["ip"]]) >= maxretry: banned.add(e["ip"])
    return out

def lockout_replay(log, maxfail=5, window=900, lock=900):
    """Per-account lockout baseline (OWASP-style): lock the username after maxfail failures from any IP."""
    fails, locked_until, out = defaultdict(list), {}, []
    for e in sorted(log, key=lambda x: x["t"]):
        u = e["user"]
        if locked_until.get(u, 0) > e["t"]: out.append(True); continue
        out.append(False)
        if e["failed"]:
            fails[u] = [t for t in fails[u] if e["t"] - t <= window] + [e["t"]]
            if len(fails[u]) >= maxfail: locked_until[u] = e["t"] + lock
    return out

def metrics(log, flagged):
    tp = sum(1 for e, f in zip(log, flagged) if e["label"] and f)
    fn = sum(1 for e, f in zip(log, flagged) if e["label"] and not f)
    fp = sum(1 for e, f in zip(log, flagged) if not e["label"] and f)
    tn = sum(1 for e, f in zip(log, flagged) if not e["label"] and not f)
    camp = defaultdict(list)
    for e, f in zip(log, flagged): camp[e["campaign"]].append((e["label"], f))
    fam = defaultdict(lambda: {"n": 0, "detected": 0, "delays": [], "fp_requests": 0, "requests": 0})
    for c, rows in camp.items():
        k = c.rsplit("-", 1)[0] if c[-1].isdigit() else c
        F = fam[k]; F["n"] += 1; F["requests"] += len(rows)
        first = next((i for i, (_, f) in enumerate(rows) if f), None)
        if rows[0][0]:
            if first is not None: F["detected"] += 1; F["delays"].append(first)
        else:
            F["fp_requests"] += sum(1 for _, f in rows if f)
            if first is not None: F["detected"] += 1   # benign campaign that received friction
    acc = (tp + tn) / max(1, tp + tn + fp + fn)
    return dict(tp=tp, fn=fn, fp=fp, tn=tn, accuracy=acc,
                precision=tp / max(1, tp + fp), recall=tp / max(1, tp + fn),
                fpr=fp / max(1, fp + tn), families=fam)

def benign_outcomes(log):
    """For the proposed system: benign friction (solvable challenge) vs denial (throttle/block)."""
    B = [e for e in log if not e["label"]]
    ch = [e for e in B if e["tier"] == 2]
    return dict(benign=len(B), challenged=len(ch), denied=sum(1 for e in B if e["tier"] in (3, 4)),
                challenge_then_success=sum(1 for e in ch if e.get("solved") == "success"),
                reasons={r: sum(1 for e in ch if e.get("reason") == r) for r in {e.get("reason") for e in ch}})

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--seed", type=int, default=1); ap.add_argument("--out", default="results.json")
    ap.add_argument("--benign-only", action="store_true")
    a = ap.parse_args()
    t0 = time.time(); run_all(a.seed, a.benign_only)
    LOG.sort(key=lambda x: x["t"])
    ours = [e["tier"] in (2, 3, 4) for e in LOG]
    f2b = fail2ban_replay(LOG)
    res = {"seed": a.seed, "duration_s": time.time() - t0, "n": len(LOG),
           "attack": sum(e["label"] for e in LOG), "benign": sum(1 - e["label"] for e in LOG),
           "proposed": metrics(LOG, ours), "fail2ban": metrics(LOG, f2b),
           "detect_ms": sorted(e["detect_ms"] for e in LOG if isinstance(e["detect_ms"], (int, float))),
           "log": LOG}
    res["benign_outcomes"] = benign_outcomes(LOG); print("benign outcomes", res["benign_outcomes"])
    json.dump(res, open(a.out, "w"), default=lambda o: dict(o) if isinstance(o, defaultdict) else str(o))
    for k in ("proposed", "fail2ban"):
        m = res[k]; print(k, {x: round(m[x], 4) if isinstance(m[x], float) else m[x] for x in m if x != "families"})
        for f, v in sorted(m["families"].items()):
            print(f"   {f:18s} campaigns={v['n']:3d} flagged={v['detected']:3d} reqs={v['requests']:4d} "
                  f"fp_reqs={v['fp_requests']:3d} delays={v['delays'][:6]}")
