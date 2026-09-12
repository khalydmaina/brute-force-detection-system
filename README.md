# Evasion-Aware Brute-Force Detection and Response System

A lightweight, deployable security microservice for Small and Medium Enterprises (SMEs) that detects and automatically responds to brute-force, credential-stuffing, and low-and-slow authentication attacks in real time.

Built as a final-year BSc Cyber Security project at the **Air Force Institute of Technology (AFIT), Kaduna, Nigeria**.



---

## The Problem

Modern attackers do not hammer a login page from one IP address. They:

- Distribute attempts across hundreds of proxy IPs (low-and-slow botnets)
- Test one stolen password across thousands of accounts (credential stuffing)
- Space requests 15+ minutes apart to stay below rate-limit windows

Standard tools like **Fail2Ban** monitor only per-IP failure counts and are completely blind to these patterns. This system was built to close that gap.

---

## How It Works

The system sits in front of your web application as an inline FastAPI gateway. Every authentication request is intercepted and evaluated using two mathematical scores before it ever reaches your backend.

### Reputation Score (Rs)

Tracks the historical trustworthiness of an IP address:

```
Rs = max(0, min(100, R_max - N_fails*W_fail + N_success*W_success + lambda(dt)))
```

- Starts at 100, drops 10 points per failed attempt
- Recovers linearly over time (50% restored after 30 minutes of inactivity)
- Prevents permanent lockout of legitimate users who make typos

### Evasion Score (Es)

Detects the structural geometry of attack traffic:

```
Es = alpha*D_IP + beta*D_User + gamma*T_anomaly
```

| Component | Weight | Detects |
|---|---|---|
| D_IP (IP Diversity) | alpha = 30 | Distributed botnet attacks |
| D_User (Username Diversity) | beta = 50 | Credential stuffing campaigns |
| T_anomaly (Timing Anomaly) | gamma = 20 | Automated bot timing regularity |

### Four-Tier Response Pipeline

| Tier | Trigger | HTTP Code | Action |
|---|---|---|---|
| Tier 1: Normal | Rs > 80, Es negligible | 200 | Request forwarded to backend |
| Tier 2: CAPTCHA | Rs < 50 (5+ failures) | 429 | CAPTCHA challenge issued |
| Tier 3: Throttle | Es > 40 | 429 | 1 attempt per 5 minutes |
| Tier 4: Hard Block | Es > 70, Rs = 0, or honeypot accessed | 403 | 24-hour IP block via Redis |

---

## Empirical Results (journal revision, v5)

Controlled lab evaluation, 3 seeds, about 860 labelled requests per run (660 attack, about 200 benign),
6 attack families including IP-rotating attacks, 6 benign families. Full method and raw logs in `experiments/`.
All systems are evaluated on identical traffic; Fail2Ban and account lockout are replayed on the same traces.

| System | Attack recall (per request) | Attack campaigns caught | Benign requests denied | Benign requests challenged |
|---|---|---|---|---|
| Original scoring (v4) | 54.9% | 54 of 60 (misses all rotating-IP attacks) | 21.3% | 0% |
| Failed-only diversity | 54.9% | 54 of 60 | 1.5% | 0% |
| **Upgraded (v5, default)** | **95.0%** | **60 of 60** | **2.3%** | 60.7% (solvable CAPTCHA) |
| Fail2Ban (5 failures / 10 min per IP) | 50.0% | 39 of 60 | 0% | 0% |
| Account lockout (5 failures / 15 min per account) | 63.1% | 45 of 60 | 74.4% | 0% |

Returning users logging in from a previously successful IP received no friction in the upgraded system
(0 of 95 requests), versus 69% denied under account lockout. In a benign-only control run, the upgraded
system challenged 0 of 200 requests and denied 4 (2.0%).

These are laboratory results on synthetic traffic. They do not establish real-world detection rates.

---

## Tech Stack

| Component | Technology |
|---|---|
| Gateway | Python 3.11, FastAPI 0.115.5, Uvicorn |
| State Management | Redis 7.x (256 MB cap, volatile-LRU eviction) |
| Audit Logging | SQLite via SQLAlchemy ORM |
| Password Hashing | bcrypt |
| Containerisation | Docker, Docker Compose |
| Demo Portal | NexusCloud (single-page HTML application) |

---

## Project Structure

```
brute-force-detection-system/
├── main.py               # FastAPI gateway and all endpoint definitions
├── scoring.py            # Reputation Score and Evasion Score engines
├── redis_client.py       # Redis connection and pipeline logic
├── models.py             # SQLAlchemy AuditLog schema
├── database.py           # Database initialisation
├── config.py             # Thresholds, weights, and constants
├── seed_users.py         # Seeds 4 demo user accounts with bcrypt hashes
├── simulate_audit.py     # Runs all 4 attack scenarios automatically
├── index.html            # SOC dashboard
├── login.html            # NexusCloud demo portal
├── requirements.txt      # Python dependencies
├── Dockerfile            # Container build instructions
└── docker-compose.yml    # Redis + FastAPI orchestration
```

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/khalydmaina/brute-force-detection-system.git
cd brute-force-detection-system
docker-compose up --build
```

The gateway will be available at `http://localhost:8000`
The SOC dashboard will be available at `http://localhost:3000`

### Option 2: Manual Setup

**Prerequisites:** Python 3.11+, Redis 7.x running locally

```bash
# Clone the repository
git clone https://github.com/khalydmaina/brute-force-detection-system.git
cd brute-force-detection-system

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Start Redis (if not already running)
redis-server

# Seed demo user accounts
python3 seed_users.py

# Launch the FastAPI gateway
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Access Points

| Service | URL |
|---|---|
| FastAPI Gateway | http://localhost:8000 |
| Interactive API Docs | http://localhost:8000/docs |
| SOC Dashboard | http://localhost:3000 |
| NexusCloud Demo Portal | Open login.html in your browser |

---

## Running the Attack Simulations

To reproduce the four empirical test scenarios:

```bash
python3 simulate_audit.py
```

This script automatically executes:
1. Scenario 1: Vertical Brute-Force (40 sequential failures, single IP)
2. Scenario 2: Horizontal Credential Stuffing (10 accounts, 3 attempts each)
3. Scenario 3: Low-and-Slow Botnet (4-second intervals, timing analysis)
4. Scenario 4: Honeypot Username Access (immediate Tier 4 trigger)

Results are persisted to the SQLite audit log and exported to CSV for analysis.

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Main authenticated login endpoint |
| `/test/login` | POST | Simulation endpoint (accepts `simulated_ip` field) |
| `/status/{ip}` | GET | Query current Rs and Es scores for an IP |
| `/block/{ip}` | POST | Manually apply a Tier 4 block |
| `/unblock/{ip}` | POST | Remove a block from Redis |
| `/logs` | GET | Retrieve recent audit log entries |

---

## Production Deployment

In production, the FastAPI gateway should not be exposed directly to the internet. The recommended architecture is:

```
Internet
    |
[Nginx / Cloudflare]     <- SSL termination, injects X-Forwarded-For
    |
[FastAPI Gateway]        <- This system (internal IP only)
    |
[Your Web Application]   <- Only receives clean Tier 1 traffic
```

The gateway enforces a **Trusted Proxy whitelist** -- it only accepts `X-Forwarded-For` headers from the known internal Nginx IP, preventing IP spoofing attacks.

---

## Security Configuration (v5, journal revision)

Set these environment variables (see `docker-compose.yml`):

| Variable | Purpose |
|---|---|
| `ADMIN_API_KEY` | Required. Every `/admin/*` route needs header `X-Admin-Key`. |
| `TRUSTED_PROXIES` | Comma-separated CIDRs of your reverse proxies. `X-Forwarded-For` is ignored unless the direct peer is in this list, and the right-most untrusted hop is used. |
| `TURNSTILE_SECRET` | Cloudflare Turnstile secret. CAPTCHA tokens are verified server-side. Without it, Tier 2 cannot be passed outside simulation mode. |
| `ENABLE_SIMULATION` | `1` only in the lab. Enables `/test/login` (caller-chosen IP) and the static test CAPTCHA token. Must be `0` in production. |
| `DIVERSITY_FAILED_ONLY` | Default `1`. Only failed attempts count toward D_IP and D_User (prevents shared-NAT false positives). |
| `ACCOUNT_SIGNALS` | Default `1`. Enables the Account Pressure and Global Pressure challenge signals for distributed, IP-rotating attacks. |

Do not publish Redis to the host or internet; anyone who can reach it can clear blocks.

## Reproducing the Journal Revision Experiments

See `experiments/README.md`.

## Configuration

All thresholds and weights are in `config.py`:

```python
REPUTATION_WEIGHT_FAIL    = 10     # Points lost per failure
REPUTATION_WEIGHT_SUCCESS = 2      # Points gained per success
FORGIVENESS_WINDOW        = 3600   # Seconds for full trust recovery

EVASION_WEIGHT_IP         = 30     # alpha: IP diversity weight
EVASION_WEIGHT_USER       = 50     # beta: username diversity weight
EVASION_WEIGHT_TIMING     = 20     # gamma: timing anomaly weight

TIER2_RS_THRESHOLD        = 50     # CAPTCHA trigger
TIER3_ES_THRESHOLD        = 40     # Throttle trigger
TIER4_ES_THRESHOLD        = 70     # Hard block trigger

BLOCK_TTL_SECONDS         = 86400  # 24-hour block duration
REDIS_MEMORY_LIMIT        = "256mb"
```

---

## Academic Context

This system was built as a final-year project for the BSc Cyber Security programme at AFIT, Kaduna. It extends the mathematical scoring paradigm established by:

> Fahrnberger, G. (2022). Realtime risk monitoring of SSH brute force attacks. In: *Innovations for Community Services*. CCIS, vol. 1585, pp. 75-95. Springer, Cham. https://doi.org/10.1007/978-3-031-06668-9_8

The system extends Fahrnberger's SSH-focused framework to HTTP web authentication, introduces a two-dimensional scoring model (Rs and Es), and adds a live four-tier automated response pipeline -- three limitations identified in the baseline paper.

---

## License

MIT License. See `LICENSE` for details.

---

## Contact

**Khalid Muhammad Maina**
Department of Cyber Security
Air Force Institute of Technology, Kaduna, Nigeria
GitHub: [@khalydmaina](https://github.com/khalydmaina)
