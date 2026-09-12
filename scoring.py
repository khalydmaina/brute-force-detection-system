"""
the detection system — Mathematical Scoring Engine
========================================
Implements:
  • Reputation Score (Rs)  — historical IP trustworthiness with time-decay recovery
  • Evasion Score   (Es)  — spatial/temporal geometry of attack traffic
"""
import time
import statistics
import redis.asyncio as aioredis

from config import (
    R_MAX, W_FAIL, W_SUCCESS, FORGIVENESS_WINDOW,
    ALPHA, BETA, GAMMA,
    THRESHOLD_IP, THRESHOLD_USER,
    BLOCK_TTL, TRACKING_TTL, THROTTLE_TTL,
    TIMESTAMP_SAMPLE_SIZE, MIN_SAMPLES_FOR_ANOMALY,
    DIVERSITY_FAILED_ONLY,
)


# ─────────────────────────────────────────────
# Redis State Helpers
# ─────────────────────────────────────────────

async def get_ip_state(redis: aioredis.Redis, ip: str) -> dict:
    """
    Fetch all tracking data for an IP in a single pipelined O(1) round-trip.

    Keys used:
      ip:{ip}:fails         — cumulative failed auth count
      ip:{ip}:successes     — cumulative successful auth count
      ip:{ip}:last_attempt  — UNIX timestamp of last request
      ip:{ip}:timestamps    — list of recent UNIX timestamps (newest-first)
      ip:{ip}:usernames     — set of unique usernames tried from this IP
    """
    pipe = redis.pipeline()
    pipe.get(f"ip:{ip}:fails")
    pipe.get(f"ip:{ip}:successes")
    pipe.get(f"ip:{ip}:last_attempt")
    pipe.lrange(f"ip:{ip}:timestamps", 0, TIMESTAMP_SAMPLE_SIZE - 1)
    pipe.scard(f"ip:{ip}:usernames")
    results = await pipe.execute()

    return {
        "fails":          int(results[0] or 0),
        "successes":      int(results[1] or 0),
        "last_attempt":   float(results[2] or time.time()),
        "timestamps":     [float(t) for t in (results[3] or [])],
        "username_count": int(results[4] or 0),
    }


async def get_username_ip_count(redis: aioredis.Redis, username: str) -> int:
    """Return the number of unique IPs that have targeted this username."""
    return await redis.scard(f"username:{username}:ips")


async def update_ip_state(
    redis: aioredis.Redis, ip: str, username: str, success: bool
) -> None:
    """
    Atomically update all tracking structures for an IP after a login attempt.
    All keys carry a 24-hour TTL to auto-purge stale entries and conserve RAM.
    """
    now = time.time()
    pipe = redis.pipeline()

    # Increment fail / success counters
    if success:
        pipe.incr(f"ip:{ip}:successes")
        pipe.expire(f"ip:{ip}:successes", TRACKING_TTL)
    else:
        pipe.incr(f"ip:{ip}:fails")
        pipe.expire(f"ip:{ip}:fails", TRACKING_TTL)

    # Record timestamp (newest-first list, trimmed to sample window)
    pipe.set(f"ip:{ip}:last_attempt", now, ex=TRACKING_TTL)
    pipe.lpush(f"ip:{ip}:timestamps", now)
    pipe.ltrim(f"ip:{ip}:timestamps", 0, TIMESTAMP_SAMPLE_SIZE - 1)
    pipe.expire(f"ip:{ip}:timestamps", TRACKING_TTL)

    # Spatial diversity tracking
    if not (DIVERSITY_FAILED_ONLY and success):
        pipe.sadd(f"ip:{ip}:usernames", username)
        pipe.expire(f"ip:{ip}:usernames", TRACKING_TTL)
        pipe.sadd(f"username:{username}:ips", ip)
        pipe.expire(f"username:{username}:ips", TRACKING_TTL)

    await pipe.execute()


async def set_hard_block(redis: aioredis.Redis, ip: str) -> None:
    await redis.set(f"block:{ip}", "1", ex=BLOCK_TTL)


async def remove_hard_block(redis: aioredis.Redis, ip: str) -> None:
    await redis.delete(f"block:{ip}")


async def is_blocked(redis: aioredis.Redis, ip: str) -> bool:
    return bool(await redis.exists(f"block:{ip}"))


async def set_throttle(redis: aioredis.Redis, ip: str) -> None:
    await redis.set(f"throttle:{ip}", "1", ex=THROTTLE_TTL)


async def is_throttled(redis: aioredis.Redis, ip: str) -> bool:
    return bool(await redis.exists(f"throttle:{ip}"))


async def clear_ip_state(redis: aioredis.Redis, ip: str) -> None:
    """Remove all tracking keys for an IP (admin reset)."""
    keys = [
        f"block:{ip}", f"throttle:{ip}",
        f"ip:{ip}:fails", f"ip:{ip}:successes",
        f"ip:{ip}:last_attempt", f"ip:{ip}:timestamps",
        f"ip:{ip}:usernames",
    ]
    if keys:
        await redis.delete(*keys)


# ─────────────────────────────────────────────
# Reputation Score  Rs
# ─────────────────────────────────────────────

def compute_reputation_score(fails: int, successes: int, last_attempt: float) -> float:
    """
    Rs = max(0, min(100, Rmax - (Nfails × Wfail) + (Nsuccess × Wsuccess) + recovery))

    Recovery mechanics
    ------------------
    • total_penalty  = fails × W_FAIL
    • After exactly FORGIVENESS_WINDOW seconds the full penalty is recovered.
    • After half the window, 50 % is recovered (linear interpolation).
    • Recovery is capped at total_penalty so Rs cannot exceed Rmax via decay alone.
    """
    now           = time.time()
    delta_t       = now - last_attempt
    total_penalty = fails * W_FAIL

    # Linear time-decay recovery — capped at the total penalty incurred
    recovery = min(total_penalty, total_penalty * (delta_t / FORGIVENESS_WINDOW))

    rs = R_MAX - total_penalty + recovery + (successes * W_SUCCESS)
    return max(0.0, min(100.0, rs))


# ─────────────────────────────────────────────
# Evasion Score  Es
# ─────────────────────────────────────────────

def compute_timing_anomaly(timestamps: list[float]) -> float:
    """
    Measures how bot-like the inter-arrival timing is.

    A bot sends requests at highly regular intervals → low coefficient of
    variation (CV) → HIGH anomaly score (close to 1.0).
    A human is irregular → high CV → LOW anomaly score (close to 0.0).

    Returns a value in [0.0, 1.0].
    """
    if len(timestamps) < MIN_SAMPLES_FOR_ANOMALY:
        return 0.0

    # Timestamps stored newest-first; sort chronologically for interval calc
    sorted_ts = sorted(timestamps)
    intervals = [
        sorted_ts[i + 1] - sorted_ts[i]
        for i in range(len(sorted_ts) - 1)
    ]
    if len(intervals) < 2:
        return 0.0

    mean_interval = sum(intervals) / len(intervals)
    if mean_interval == 0.0:
        return 1.0   # Zero-interval flood = definite bot

    try:
        std_dev = statistics.stdev(intervals)
        cv = std_dev / mean_interval
        # Low CV → bot-like → anomaly near 1.0;  High CV → human → anomaly near 0.0
        anomaly = max(0.0, min(1.0, 1.0 - cv))
        return anomaly
    except statistics.StatisticsError:
        return 0.0


def compute_evasion_score(
    ip_diversity: int,
    username_diversity: int,
    timing_anomaly: float,
) -> float:
    """
    Es = (α × D_IP) + (β × D_User) + (γ × T_anomaly)

    All component ratios are normalised to [0, 1] before weighting.
    Maximum possible Es = α + β + γ = 100.
    """
    d_ip   = min(1.0, ip_diversity   / THRESHOLD_IP)
    d_user = min(1.0, username_diversity / THRESHOLD_USER)
    t_anom = min(1.0, timing_anomaly)

    es = (ALPHA * d_ip) + (BETA * d_user) + (GAMMA * t_anom)
    return max(0.0, min(100.0, es))


# ─────────────────────────────────────────────
# Revision: Account Pressure and Global Pressure signals
# ─────────────────────────────────────────────
from config import (ACCT_SUSPECT_IP_THRESHOLD, ACCT_WINDOW, ACCT_HOLD,
                    GLOBAL_COLD_THRESHOLD, GLOBAL_COLD_RATIO, GLOBAL_WINDOW, GLOBAL_HOLD, GOOD_IP_TTL)
import uuid as _uuid

async def get_context_signals(redis: aioredis.Redis, ip: str, username: str) -> dict:
    """One pipelined round-trip: is this account / the whole endpoint under distributed attack,
    and has this IP previously authenticated successfully to this account?"""
    pipe = redis.pipeline()
    pipe.exists(f"acct:{username}:under_attack")
    pipe.sismember(f"acct:{username}:good_ips", ip)
    pipe.exists("global:under_attack")
    pipe.scard(f"acct:{username}:suspect_ips")
    pipe.zcard("global:cold_suspects")
    r = await pipe.execute()
    return {"acct_attack": bool(r[0]), "known_ip": bool(r[1]), "global_attack": bool(r[2]),
            "acct_suspect_ips": int(r[3] or 0), "global_cold": int(r[4] or 0)}

async def record_suspect(redis: aioredis.Redis, ip: str, username: str, warm: bool) -> None:
    """Called for failed or unsolved-challenge attempts. Updates the account's set of distinct
    suspect IPs and the global sliding window of suspect attempts from cold (never-successful) IPs."""
    now = time.time()
    pipe = redis.pipeline()
    pipe.sadd(f"acct:{username}:suspect_ips", ip)
    pipe.expire(f"acct:{username}:suspect_ips", ACCT_WINDOW)
    pipe.scard(f"acct:{username}:suspect_ips")
    if not warm:
        member = f"{now}:{ip}:{_uuid.uuid4().hex[:6]}"
        pipe.zadd("global:cold_suspects", {member: now})
        pipe.zremrangebyscore("global:cold_suspects", 0, now - GLOBAL_WINDOW)
        pipe.zcard("global:cold_suspects")
        pipe.zadd("global:cold_all", {member: now})
        pipe.zremrangebyscore("global:cold_all", 0, now - GLOBAL_WINDOW)
        pipe.zcard("global:cold_all")
    r = await pipe.execute()
    pipe = redis.pipeline()
    if r[2] >= ACCT_SUSPECT_IP_THRESHOLD:
        pipe.set(f"acct:{username}:under_attack", "1", ex=ACCT_HOLD)
    if not warm:
        suspects, total = r[5], max(1, r[8])
        # Global Pressure: enough suspect attempts from cold IPs AND they dominate cold-IP traffic
        if suspects >= GLOBAL_COLD_THRESHOLD and suspects / total >= GLOBAL_COLD_RATIO:
            pipe.set("global:under_attack", "1", ex=GLOBAL_HOLD)
    await pipe.execute()

async def record_cold_attempt(redis: aioredis.Redis, ip: str) -> None:
    """Successful attempt from a cold IP: counts toward the cold-IP denominator only."""
    now = time.time()
    pipe = redis.pipeline()
    pipe.zadd("global:cold_all", {f"{now}:{ip}:{_uuid.uuid4().hex[:6]}": now})
    pipe.zremrangebyscore("global:cold_all", 0, now - GLOBAL_WINDOW)
    await pipe.execute()

async def record_good(redis: aioredis.Redis, ip: str, username: str) -> None:
    pipe = redis.pipeline()
    pipe.sadd(f"acct:{username}:good_ips", ip)
    pipe.expire(f"acct:{username}:good_ips", GOOD_IP_TTL)
    await pipe.execute()
