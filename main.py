"""
THE DETECTION SYSTEM — FastAPI Authentication Gateway
===================================================
"""
import time
import bcrypt
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from config import (
    HONEYPOT_USERNAMES,
    RS_TIER1_MIN, RS_TIER2_LIMIT, ES_TIER3_MIN, ES_TIER4_MIN,
)
from models import LoginRequest, TestLoginRequest, InterceptResponse, IPStatusResponse
from redis_client import get_redis, close_redis
from database import get_db, AuditLog, User
from scoring import (
    get_ip_state, get_username_ip_count, update_ip_state,
    compute_reputation_score, compute_evasion_score, compute_timing_anomaly,
    set_hard_block, remove_hard_block, is_blocked, set_throttle, is_throttled,
    clear_ip_state,
)

# ─────────────────────────────────────────────
# Application lifecycle
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_redis()

app = FastAPI(
    title="THE DETECTION SYSTEM",
    description="Evasion-Aware Brute-Force Detection & Response System",
    version="4.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Core Authentication Pipelines
# ─────────────────────────────────────────────

async def _process_login(
    username: str, 
    password: str, 
    client_ip: str, 
    db: Session,
    captcha_token: str = None
) -> JSONResponse:
    t0 = time.perf_counter()
    redis = await get_redis()
    
    status_code = 200
    response_data = {
        "status": "", "message": "", "tier": 1, 
        "rs": 0.0, "es": 0.0, "latency_ms": 0.0
    }

    if await is_blocked(redis, client_ip):
        status_code = 403
        response_data.update({"status": "blocked", "message": "Extreme threat detected. Access denied permanently.", "tier": 4, "rs": 0.0, "es": 100.0, "latency_ms": _ms(t0)})
        _log_to_db(db, client_ip, username, response_data)
        return JSONResponse(status_code=status_code, content=response_data)

    if username.lower() in HONEYPOT_USERNAMES:
        await set_hard_block(redis, client_ip)
        status_code = 403
        response_data.update({"status": "blocked", "message": "Security violation detected. Hard block applied.", "tier": 4, "rs": 0.0, "es": 100.0, "honeypot_triggered": True, "latency_ms": _ms(t0)})
        _log_to_db(db, client_ip, username, response_data)
        return JSONResponse(status_code=status_code, content=response_data)

    state = await get_ip_state(redis, client_ip)
    rs = compute_reputation_score(state["fails"], state["successes"], state["last_attempt"])
    
    unique_users_count = state["username_count"]
    unique_ips_count = await get_username_ip_count(redis, username)
    current_timestamps = [time.time()] + state["timestamps"]
    t_anomaly = compute_timing_anomaly(current_timestamps)
    es = compute_evasion_score(unique_ips_count, unique_users_count, t_anomaly)

    if es >= ES_TIER3_MIN or await is_throttled(redis, client_ip):
        await set_throttle(redis, client_ip)
        status_code = 429
        response_data.update({"status": "throttled", "message": "Rate limit exceeded. Request throttled.", "tier": 3, "rs": rs, "es": es, "latency_ms": _ms(t0)})
        _log_to_db(db, client_ip, username, response_data)
        return JSONResponse(status_code=status_code, content=response_data)

    if rs < RS_TIER2_LIMIT and captcha_token != "mock-valid-token":
        status_code = 429
        response_data.update({"status": "captcha_required", "message": "CAPTCHA challenge required to verify humanity.", "tier": 2, "rs": rs, "es": es, "captcha_required": True, "latency_ms": _ms(t0)})
        _log_to_db(db, client_ip, username, response_data)
        return JSONResponse(status_code=status_code, content=response_data)

    user_record = db.query(User).filter(User.username == username).first()
    success = False
    
    if user_record:
        candidate_bytes = password.encode('utf-8')
        stored_hash_bytes = user_record.password_hash.encode('utf-8')
        success = bcrypt.checkpw(candidate_bytes, stored_hash_bytes)

    await update_ip_state(redis, client_ip, username, success)
    
    state_updated = await get_ip_state(redis, client_ip)
    final_rs = compute_reputation_score(state_updated["fails"], state_updated["successes"], state_updated["last_attempt"])

    if success:
        status_code = 200
        response_data.update({"status": "success", "message": "Authentication successful.", "tier": 1, "rs": final_rs, "es": es, "latency_ms": _ms(t0)})
    else:
        if final_rs <= 0:
            await set_hard_block(redis, client_ip)
            status_code = 403
            response_data.update({"status": "blocked", "message": "Maximum failure limits breached. Hard block deployed.", "tier": 4, "rs": final_rs, "es": es, "latency_ms": _ms(t0)})
        else:
            status_code = 401
            response_data.update({"status": "invalid_credentials", "message": "Invalid credentials provided.", "tier": 1, "rs": final_rs, "es": es, "latency_ms": _ms(t0)})

    _log_to_db(db, client_ip, username, response_data)
    return JSONResponse(status_code=status_code, content=response_data)


# ─────────────────────────────────────────────
# Route Mappings
# ─────────────────────────────────────────────

@app.post("/auth/register", tags=["Authentication"])
async def register_user(payload: LoginRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == payload.username.strip().lower()).first()
    if existing_user:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Username is already taken."}
        )
    
    password_bytes = payload.password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
    
    new_user = User(
        username=payload.username.strip().lower(),
        password_hash=hashed_password
    )
    db.add(new_user)
    db.commit()
    return {"message": "Account created successfully! You may now sign in."}

@app.post("/auth/login", response_model=InterceptResponse, tags=["Authentication"])
async def production_login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = _extract_ip(request)
    return await _process_login(payload.username, payload.password, client_ip, db, payload.captcha_token)

@app.post("/test/login", response_model=InterceptResponse, tags=["Simulation"])
async def simulation_login(payload: TestLoginRequest, db: Session = Depends(get_db)):
    return await _process_login(payload.username, payload.password, payload.simulated_ip, db, payload.captcha_token)

@app.get("/admin/logs/live", tags=["Admin"])
async def get_live_logs(limit: int = 20, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return [{"id": log.id, "timestamp": log.timestamp.isoformat(), "ip": log.ip_address, "username": log.target_username, "status": log.status, "rs": log.rs, "es": log.es, "tier": log.tier, "latency_ms": log.latency_ms, "honeypot": log.honeypot_triggered} for log in logs]

@app.get("/admin/stats", tags=["Admin"])
async def get_stats(db: Session = Depends(get_db)):
    total    = db.query(AuditLog).count()
    blocked  = db.query(AuditLog).filter(AuditLog.tier == 4).count()
    throttled= db.query(AuditLog).filter(AuditLog.tier == 3).count()
    captcha  = db.query(AuditLog).filter(AuditLog.tier == 2).count()
    success  = db.query(AuditLog).filter(AuditLog.status == "success").count()
    honeypots= db.query(AuditLog).filter(AuditLog.honeypot_triggered == True).count()

    avg_lat_row = db.query(func.avg(AuditLog.latency_ms)).scalar()
    avg_latency = round(avg_lat_row or 0, 2)
    detection_rate = round((blocked + throttled) / max(total, 1) * 100, 1)

    recent = db.query(AuditLog.rs, AuditLog.es, AuditLog.tier, AuditLog.timestamp, AuditLog.ip_address).filter(AuditLog.rs != None).order_by(AuditLog.id.desc()).limit(40).all()
    recent_list = [{"rs": r.rs, "es": r.es, "tier": r.tier, "timestamp": r.timestamp.isoformat(), "ip": r.ip_address} for r in reversed(recent)]

    tier_rows = db.query(AuditLog.tier, func.count(AuditLog.tier)).group_by(AuditLog.tier).all()
    tier_dist = {str(t): c for t, c in tier_rows}
    unique_ips = db.query(func.count(func.distinct(AuditLog.ip_address))).scalar() or 0

    return {"total": total, "blocked": blocked, "throttled": throttled, "captcha": captcha, "successful": success, "honeypot_hits": honeypots, "avg_latency_ms": avg_latency, "detection_rate": detection_rate, "unique_ips": unique_ips, "recent_scores": recent_list, "tier_distribution": tier_dist}

@app.get("/admin/all-ips", tags=["Admin"])
async def get_all_ips(db: Session = Depends(get_db)):
    sqlite_ips = db.query(func.distinct(AuditLog.ip_address)).all()
    historical_ips = [ip[0] for ip in sqlite_ips]
    
    redis = await get_redis()
    active_redis_ips = set()
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor, match="ip:*", count=100)
        for key in keys:
            key_str = key.decode("utf-8") if isinstance(key, bytes) else key
            active_redis_ips.add(key_str.replace("ip:", ""))
        if cursor == 0:
            break
            
    return {"sqlite_historical_count": len(historical_ips), "sqlite_historical_ips": historical_ips, "redis_active_count": len(active_redis_ips), "redis_active_ips": list(active_redis_ips)}

@app.get("/admin/blocked-ips", tags=["Admin"])
async def get_blocked_ips():
    redis = await get_redis()
    blocked_ips = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor, match="block:*", count=100)
        for key in keys:
            ip = key.decode("utf-8").replace("block:", "") if isinstance(key, bytes) else key.replace("block:", "")
            ttl = await redis.ttl(key)
            blocked_ips.append({"ip": ip, "ttl_seconds": ttl, "ttl_human": _format_ttl(ttl)})
        if cursor == 0:
            break
    blocked_ips.sort(key=lambda x: x["ttl_seconds"], reverse=True)
    return {"blocked_ips": blocked_ips, "total": len(blocked_ips)}

@app.get("/admin/throttled-ips", tags=["Admin"])
async def get_throttled_ips():
    redis = await get_redis()
    throttled_ips = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor, match="throttle:*", count=100)
        for key in keys:
            ip = key.decode("utf-8").replace("throttle:", "") if isinstance(key, bytes) else key.replace("throttle:", "")
            ttl = await redis.ttl(key)
            throttled_ips.append({"ip": ip, "ttl_seconds": ttl, "ttl_human": _format_ttl(ttl)})
        if cursor == 0:
            break
    throttled_ips.sort(key=lambda x: x["ttl_seconds"], reverse=True)
    return {"throttled_ips": throttled_ips, "total": len(throttled_ips)}

@app.get("/admin/status/{ip}", response_model=IPStatusResponse, tags=["Admin"])
async def get_ip_metrics(ip: str):
    redis = await get_redis()
    state = await get_ip_state(redis, ip)
    blocked = await is_blocked(redis, ip)
    throttled = await is_throttled(redis, ip)
    rs = compute_reputation_score(state["fails"], state["successes"], state["last_attempt"])
    t_anomaly = compute_timing_anomaly(state["timestamps"])
    unique_users = state["username_count"]
    unique_ips = await get_username_ip_count(redis, ip)
    es = compute_evasion_score(unique_ips, unique_users, t_anomaly)
    return IPStatusResponse(ip=ip, blocked=blocked, throttled=throttled, fails=state["fails"], successes=state["successes"], reputation_score=round(rs, 2), username_diversity=unique_users, ip_diversity=unique_ips, timing_anomaly=round(t_anomaly, 4), evasion_score=round(es, 2))

@app.delete("/admin/unblock/{ip}", tags=["Admin"])
async def unblock_ip(ip: str):
    redis = await get_redis()
    await clear_ip_state(redis, ip)
    await remove_hard_block(redis, ip)
    await redis.delete(f"throttle:{ip}")
    return {"message": f"IP {ip} fully reset. All counters, throttles, and blocks cleared."}

# ── NEW MASTER RESET ENDPOINT ──
@app.delete("/admin/factory-reset", tags=["Admin"])
async def factory_reset(db: Session = Depends(get_db)):
    """Flushes all Redis RAM locks/scores and deletes all SQLite traffic logs. Keeps Users intact."""
    # 1. Flush Redis Short-Term Memory
    redis = await get_redis()
    await redis.flushall()
    
    # 2. Delete all SQLite Historical Traffic Logs
    db.query(AuditLog).delete()
    db.commit()
    
    return {"message": "Factory reset complete. Redis flushed and all audit logs deleted."}


@app.get("/health", tags=["System"])
async def health():
    redis = await get_redis()
    try:
        await redis.ping()
        redis_ok = True
    except Exception:
        redis_ok = False
    return {"status": "ok" if redis_ok else "degraded", "redis": "connected" if redis_ok else "unreachable"}

# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────

def _log_to_db(db: Session, ip: str, username: str, response_data: dict):
    log_entry = AuditLog(
        ip_address=ip,
        target_username=username,
        status=response_data.get("status"),
        rs=response_data.get("rs", 0.0),
        es=response_data.get("es", 0.0),
        tier=response_data.get("tier", 1),
        latency_ms=response_data.get("latency_ms", 0.0),
        honeypot_triggered=response_data.get("honeypot_triggered", False)
    )
    db.add(log_entry)
    db.commit()

def _extract_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff: return xff.split(",")[0].strip()
    return request.client.host or "0.0.0.0"

def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)

def _format_ttl(seconds: int) -> str:
    if seconds < 0: return "expired"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h > 0: return f"{h}h {m}m remaining"
    elif m > 0: return f"{m}m {s}s remaining"
    return f"{s}s remaining"
