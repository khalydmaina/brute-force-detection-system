"""
Load and stress test (revision experiments).
Closed-loop clients at increasing concurrency hit /test/login with unique simulated IPs.
Reports throughput, latency percentiles, failure rate, gateway CPU/RSS, Redis memory,
and recovery (a low-concurrency run repeated after the heaviest level).
Usage: python load_test.py --duration 20 --levels 10,50,100,250,500 --bcrypt-share 0.0
"""
import argparse, asyncio, json, random, subprocess, time
import httpx, psutil

URL = "http://localhost:8000/test/login"

def gateway_proc():
    for p in psutil.process_iter(["cmdline"]):
        if p.info["cmdline"] and "uvicorn" in " ".join(p.info["cmdline"]) and "main:app" in " ".join(p.info["cmdline"]):
            return p

def redis_mem():
    out = subprocess.run(["redis-cli", "info", "memory"], capture_output=True, text=True).stdout
    return int(next(l.split(":")[1] for l in out.splitlines() if l.startswith("used_memory:")))

async def level(conc, duration, bcrypt_share, timeout):
    lat, codes, errors, stop = [], {}, 0, time.time() + duration
    proc = gateway_proc(); proc.cpu_percent(None); cpu, rss = [], []
    async def sampler():
        while time.time() < stop:
            await asyncio.sleep(0.5); cpu.append(proc.cpu_percent(None)); rss.append(proc.memory_info().rss)
    async def worker(c):
        nonlocal errors
        while time.time() < stop:
            ip = f"100.{random.randint(64,127)}.{random.randint(0,255)}.{random.randint(1,254)}"
            if random.random() < bcrypt_share:
                body = {"username": "alice", "password": "Pw-alice-2026", "simulated_ip": ip}
            else:
                body = {"username": f"nouser{random.randint(1,10**6)}", "password": "x", "simulated_ip": ip}
            t = time.perf_counter()
            try:
                r = await c.post(URL, json=body, timeout=timeout)
                lat.append((time.perf_counter() - t) * 1000); codes[r.status_code] = codes.get(r.status_code, 0) + 1
            except Exception:
                errors += 1
    lim = httpx.Limits(max_connections=conc, max_keepalive_connections=conc)
    async with httpx.AsyncClient(limits=lim) as c:
        await asyncio.gather(sampler(), *[worker(c) for _ in range(conc)])
    lat.sort(); n = len(lat); q = lambda p: round(lat[min(n - 1, int(p * n))], 2) if n else None
    return dict(concurrency=conc, completed=n, errors=errors, error_rate=round(errors / max(1, n + errors), 4),
                throughput_rps=round(n / duration, 1), p50_ms=q(.5), p95_ms=q(.95), p99_ms=q(.99),
                max_ms=round(lat[-1], 1) if n else None, codes=codes,
                cpu_mean_pct=round(sum(cpu) / max(1, len(cpu)), 1), rss_peak_mb=round(max(rss) / 2**20, 1) if rss else None)

async def main(a):
    res, r0 = [], redis_mem()
    for conc in [int(x) for x in a.levels.split(",")]:
        r = await level(conc, a.duration, a.bcrypt_share, a.timeout); res.append(r); print(r, flush=True)
        await asyncio.sleep(3)
    rec = await level(int(a.levels.split(",")[0]), a.duration, a.bcrypt_share, a.timeout)
    rec["phase"] = "recovery"; res.append(rec); print(rec, flush=True)
    out = dict(levels=res, redis_used_memory_before=r0, redis_used_memory_after=redis_mem(),
               redis_keys=int(subprocess.run(["redis-cli", "dbsize"], capture_output=True, text=True).stdout.strip() or 0),
               bcrypt_share=a.bcrypt_share, duration_s=a.duration)
    json.dump(out, open(a.out, "w"), indent=1)
    print("redis MB before/after", round(r0 / 2**20, 1), round(out["redis_used_memory_after"] / 2**20, 1), "keys", out["redis_keys"])

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=20); ap.add_argument("--levels", default="10,50,100,250,500")
    ap.add_argument("--bcrypt-share", type=float, default=0.0); ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--out", default="load.json")
    asyncio.run(main(ap.parse_args()))
