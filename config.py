# ============================================================
# THE DETECTION SYSTEM — Configuration & Hyperparameters
# ============================================================

# --- Reputation Score (Rs) weights ---
R_MAX         = 100     # Maximum starting trust score
W_FAIL        = 10      # Penalty per failed attempt
W_SUCCESS     = 2       # Reward per successful login
FORGIVENESS_WINDOW = 3600  # Seconds for full recovery (1 hour)

# --- Evasion Score (Es) weights (must sum to 100) ---
ALPHA = 30   # IP Diversity weight
BETA  = 50   # Username Diversity weight
GAMMA = 20   # Timing Anomaly weight

# --- Diversity thresholds ---
THRESHOLD_IP   = 5   # Unique IPs per username before max D_IP penalty
THRESHOLD_USER = 3   # Unique usernames per IP before max D_User penalty

# --- Graduated response thresholds ---
RS_TIER1_MIN   = 80  # Rs must be >= this for Tier 1 (Normal)
RS_TIER2_LIMIT = 50  # Rs below this triggers Tier 2 (CAPTCHA)
ES_TIER3_MIN   = 40  # Es above this triggers Tier 3 (Throttle)
ES_TIER4_MIN   = 70  # Es above this OR Rs==0 triggers Tier 4 (Hard Block)

# --- Redis TTLs ---
BLOCK_TTL    = 86400  # 24-hour hard block
TRACKING_TTL = 86400  # 24-hour state tracking
THROTTLE_TTL = 300    # 5-minute throttle window

# --- Honeypot usernames — any login attempt triggers Tier 4 instantly ---
HONEYPOT_USERNAMES = {
    "honeypot",
    "admin_honeypot",
    "root_trap",
    "test_decoy",
    "administrator_trap",
}

# --- Demo user store (replace with real DB in production) ---
DEMO_USERS = {
    "alice":   "password123",
    "bob":     "securepass",
    "charlie": "mypassword",
    "admin":   "adminpass",
}

# --- Redis ---
import os
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# --- Timing anomaly sample window ---
TIMESTAMP_SAMPLE_SIZE = 20   # Number of past timestamps kept per IP
MIN_SAMPLES_FOR_ANOMALY = 3  # Minimum samples before timing anomaly is computed

# --- Revision: count only FAILED attempts toward spatial diversity (D_IP, D_User) ---
# Credential stuffing produces many distinct usernames with failed logins; a shared
# NAT/office IP produces many distinct usernames with successful logins.
import os as _os
DIVERSITY_FAILED_ONLY = _os.getenv("DIVERSITY_FAILED_ONLY", "1") == "1"

# --- Revision: account-level and global signals for distributed (IP-rotating) attacks ---
ACCOUNT_SIGNALS          = _os.getenv("ACCOUNT_SIGNALS", "1") == "1"
ACCT_SUSPECT_IP_THRESHOLD = int(_os.getenv("ACCT_SUSPECT_IP_THRESHOLD", "5"))   # distinct failing IPs per account
ACCT_WINDOW              = 3600       # seconds a failing IP stays in an account's suspect set
ACCT_HOLD                = 900        # seconds an account stays in protected mode after the last trigger
GLOBAL_COLD_THRESHOLD    = int(_os.getenv("GLOBAL_COLD_THRESHOLD", "20"))       # minimum suspect attempts from cold IPs per window
GLOBAL_COLD_RATIO        = float(_os.getenv("GLOBAL_COLD_RATIO", "0.5"))        # and minimum failure ratio among cold-IP attempts
GLOBAL_WINDOW            = 60
GLOBAL_HOLD              = 300
GOOD_IP_TTL              = 7 * 86400  # how long an IP stays "known" for an account after a successful login
