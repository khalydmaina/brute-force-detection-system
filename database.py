from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# SQLite database URL (easily swapped to postgresql:// later)
SQLALCHEMY_DATABASE_URL = "sqlite:///./intercept_logs.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# ─────────────────────────────────────────────
# Schema: Audit Logs (For Empirical Data)
# ─────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String, index=True)
    target_username = Column(String, index=True)
    
    # Evasion & Reputation Tracking
    status = Column(String)  # e.g., success, throttled, blocked, captcha_required
    rs = Column(Float)
    es = Column(Float)
    tier = Column(Integer)
    latency_ms = Column(Float)
    honeypot_triggered = Column(Boolean, default=False)

# ─────────────────────────────────────────────
# Schema: Real Users (To replace DEMO_USERS)
# ─────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)  # For bcrypt later

# Create the tables in the database
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
