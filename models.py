from pydantic import BaseModel
from typing import Optional

class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_token: Optional[str] = None

class TestLoginRequest(BaseModel):
    username: str
    password: str
    simulated_ip: str
    captcha_token: Optional[str] = None

class InterceptResponse(BaseModel):
    status: str
    message: str
    tier: int
    rs: float
    es: float
    latency_ms: float
    captcha_required: Optional[bool] = False
    honeypot_triggered: Optional[bool] = False

class IPStatusResponse(BaseModel):
    ip: str
    blocked: bool
    throttled: bool
    fails: int
    successes: int
    reputation_score: float
    username_diversity: int
    ip_diversity: int
    timing_anomaly: float
    evasion_score: float
