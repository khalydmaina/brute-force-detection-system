"""
Security evaluation of the gateway itself (revision experiments).
Each test runs against a clean Redis state and prints PASS (attack mitigated)
or FAIL (attack succeeded).
Usage: python security_tests.py [--label original|patched]
"""
import argparse, json, subprocess, requests

B = "http://localhost:8000"
H = {"content-type": "application/json"}
flush = lambda: subprocess.run(["redis-cli", "flushall"], capture_output=True)

def login(user, pw, xff=None, token=None):
    h = dict(H); body = {"username": user, "password": pw}
    if xff: h["X-Forwarded-For"] = xff
    if token: body["captcha_token"] = token
    r = requests.post(f"{B}/auth/login", json=body, headers=h, timeout=15)
    return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else {})

def t1_xff_rotation():
    """Attacker rotates X-Forwarded-For on every request to evade per-IP tracking."""
    flush(); # Reverse proxy appends the attacker's real IP (203.0.113.66) after the spoofed value
    codes = [login("admin", f"g{i}", xff=f"192.0.2.{i}, 203.0.113.66")[0] for i in range(1, 61)]
    reached_auth = sum(c == 401 for c in codes)
    return reached_auth < 15, f"{reached_auth}/60 password guesses reached credential check"

def t2_xff_framing():
    """Attacker spoofs a victim's IP in X-Forwarded-For and hits the honeypot, getting the victim blocked."""
    flush(); victim = "198.51.100.7"
    login("admin_honeypot", "x", xff=f"{victim}, 203.0.113.66")  # spoofed value + real IP appended by proxy
    code, _ = login("alice", "Pw-alice-2026", xff=victim)
    return code == 200, f"victim login returned HTTP {code}"

def t3_captcha_bypass():
    """Attacker supplies a static CAPTCHA token to skip Tier 2."""
    flush(); ip = "203.0.113.200"
    for i in range(6): login("bob", f"x{i}", xff=ip)   # drive Rs below 50
    code, d = login("bob", "x-next", xff=ip, token="mock-valid-token")
    return code != 401, f"with static token: HTTP {code} tier={d.get('tier')}"

def t4_admin_unblock():
    """Hard-blocked attacker calls the admin unblock endpoint without credentials."""
    flush(); ip = "203.0.113.201"
    login("admin_honeypot", "x", xff=ip)
    r = requests.delete(f"{B}/admin/unblock/{ip}", timeout=10)
    code, _ = login("admin", "guess", xff=ip)
    return r.status_code in (401, 403), f"unauthenticated unblock HTTP {r.status_code}; attacker next login HTTP {code}"

def t5_audit_wipe():
    """Unauthenticated caller deletes the audit log via factory reset."""
    r = requests.delete(f"{B}/admin/factory-reset", timeout=10)
    return r.status_code in (401, 403), f"unauthenticated factory-reset HTTP {r.status_code}"

def t6_simulation_endpoint():
    """Simulation endpoint lets any caller choose its own source IP."""
    r = requests.post(f"{B}/test/login", json={"username": "admin", "password": "x", "simulated_ip": "1.2.3.4"}, timeout=10)
    return r.status_code == 404, f"/test/login HTTP {r.status_code}"

def t7_admin_read():
    """Unauthenticated read of live logs and blocked-IP lists (information disclosure)."""
    r = requests.get(f"{B}/admin/logs/live", timeout=10)
    return r.status_code in (401, 403), f"/admin/logs/live HTTP {r.status_code}"

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--label", default="original"); a = ap.parse_args()
    out = {}
    for t in (t1_xff_rotation, t2_xff_framing, t3_captcha_bypass, t4_admin_unblock, t5_audit_wipe, t6_simulation_endpoint, t7_admin_read):
        ok, info = t()
        out[t.__name__] = {"mitigated": ok, "detail": info, "attack": t.__doc__.strip()}
        print(f"{'PASS' if ok else 'FAIL'}  {t.__name__:22s} {info}")
    json.dump(out, open(f"security_{a.label}.json", "w"), indent=1)
