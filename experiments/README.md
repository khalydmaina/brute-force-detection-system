# Journal Revision Experiments

Everything needed to reproduce the revised evaluation. Run on the testbed VM described in the paper.

## Setup
```bash
pip install -r requirements.txt psutil
redis-server --daemonize yes --maxmemory 256mb --maxmemory-policy volatile-lru
# register the 52 test users (alice, bob, ..., user1..user40), passwords "Pw-<name>-2026"
python experiments/register_users.py
```

## 1. Detection accuracy and ablation (3 variants x 3 seeds)
Start the gateway in lab mode with the variant's flags, flush Redis before each run:
```bash
# original scoring
ENABLE_SIMULATION=1 ADMIN_API_KEY=k DIVERSITY_FAILED_ONLY=0 ACCOUNT_SIGNALS=0 uvicorn main:app --port 8000
# failed-only diversity
ENABLE_SIMULATION=1 ADMIN_API_KEY=k DIVERSITY_FAILED_ONLY=1 ACCOUNT_SIGNALS=0 uvicorn main:app --port 8000
# upgraded (default)
ENABLE_SIMULATION=1 ADMIN_API_KEY=k uvicorn main:app --port 8000
```
For each server, in another terminal (redis-cli flushall first):
```bash
cd experiments
python eval_detection.py --seed 1 --out v0_s1.json     # v0 = original, v1 = failed-only, v2 = upgraded
python eval_detection.py --seed 1 --out v2b_s1.json --benign-only   # upgraded, benign traffic only
```
Then `python aggregate.py` prints mean +/- std tables for the proposed system, the Fail2Ban
baseline (maxretry=5, findtime=600, per IP) and a per-account lockout baseline
(5 failures in 15 min locks the username for 15 min), all replayed on identical traffic.

Traffic per run: about 860 requests. Attacks (660): vertical brute force (5 IPs), single-IP credential
stuffing (5 IPs), low-and-slow (3 IPs, 4 s pacing), honeypot (5 IPs), distributed credential stuffing
(200 rotating IPs), distributed brute force (60 rotating IPs on one account). Benign (about 200):
normal users, users who mistype, shared-NAT offices, password-manager autofill, multi-device users,
and returning users with a prior successful login. Benign clients solve CAPTCHAs when challenged.

## 2. Security tests (attacks on the gateway itself)
```bash
ADMIN_API_KEY=test-admin-key TRUSTED_PROXIES=127.0.0.1/32 ENABLE_SIMULATION=0 uvicorn main:app --port 8000
python security_tests.py --label patched
```

## 3. Load and stress
```bash
ENABLE_SIMULATION=1 ADMIN_API_KEY=k uvicorn main:app --port 8000
python load_test.py --levels 10,50,100,250,500 --bcrypt-share 0.0 --out load_detect.json
python load_test.py --levels 10,50,100,250 --bcrypt-share 0.1 --timeout 30 --out load_mixed.json
```
Note: the load generator competes with the gateway for CPU if both run on the same VM.
Report the hardware and whether the client ran on a separate machine.
