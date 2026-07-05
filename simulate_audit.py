"""
THE DETECTION SYSTEM — Full-Scale Stress Test & Telemetry Exporter
=======================================================
This script simulates a multi-vector distributed attack against the 
THE DETECTION SYSTEM gateway and exports the resulting telemetry to a CSV file 
for Chapter 4 thesis analysis.
"""

import requests
import time
import random
import threading
import sqlite3
import csv
import os

# Configuration
API_URL = "http://localhost:8000/test/login"
DB_FILE = "intercept_logs.db"
CSV_FILE = "thesis_telemetry_results.csv"

# Color formatting for terminal output
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'

def print_header(text):
    print(f"\n{Colors.CYAN}=== {text} ==={Colors.RESET}")

def send_request(ip, username, password):
    """Sends a login request simulating a specific IP."""
    payload = {
        "username": username,
        "password": password,
        "simulated_ip": ip
    }
    try:
        response = requests.post(API_URL, json=payload, timeout=5)
        return response.status_code, response.json()
    except Exception as e:
        return 500, {"status": "error", "message": str(e)}

# ─────────────────────────────────────────────
# Attack Vectors
# ─────────────────────────────────────────────

def attack_sledgehammer():
    """Simulates a high-speed brute force attack from a single IP."""
    ip = "192.168.100.55"
    target = "admin"
    print(f"{Colors.YELLOW}[SLEDGEHAMMER] Initiating high-speed brute force from {ip}...{Colors.RESET}")
    
    for i in range(1, 41): # 40 rapid requests
        status, data = send_request(ip, target, f"wrongpass{i}")
        if i % 10 == 0:
            print(f"  -> Sledgehammer Sent {i}/40 | Current Status: {data.get('status', 'error')} | Rs: {data.get('rs', 0)}")
        time.sleep(0.05) # Extreme speed to spike Evasion Score (Es)

def attack_cred_stuffing():
    """Simulates a distributed credential stuffing attack across many users."""
    ip = "203.0.113.42"
    print(f"{Colors.YELLOW}[CRED-STUFFING] Initiating broad account scanning from {ip}...{Colors.RESET}")
    
    users = ["alice", "bob", "charlie", "dave", "eve", "frank", "grace", "henry", "iris", "jack"]
    
    for i, user in enumerate(users):
        for j in range(3): # 3 attempts per user
            send_request(ip, user, f"pass123_{j}")
            time.sleep(0.2)
        if i % 3 == 0:
            print(f"  -> Cred-Stuffing scanned {i+1} accounts...")

def attack_honeypot():
    """Simulates a script kiddie hitting a trap account."""
    ip = "45.33.22.11"
    print(f"{Colors.YELLOW}[HONEYPOT] Triggering instant Tier 4 block from {ip}...{Colors.RESET}")
    time.sleep(2) # Delay to let other attacks start
    send_request(ip, "admin_honeypot", "password")
    print(f"  -> Honeypot tripped! IP {ip} should be hard-blocked.")

def attack_low_and_slow():
    """Simulates a stealthy attacker trying to stay under the radar."""
    ip = "10.0.5.99"
    target = "alice"
    print(f"{Colors.YELLOW}[LOW & SLOW] Initiating stealth brute force from {ip}...{Colors.RESET}")
    
    for i in range(1, 15):
        send_request(ip, target, f"stealth_{i}")
        if i % 5 == 0:
            print(f"  -> Low & Slow Sent {i}/15 | Waiting 2 seconds...")
        time.sleep(2.0) # Long delay to keep Es low, but Rs will eventually drain

# ─────────────────────────────────────────────
# Data Export
# ─────────────────────────────────────────────

def export_telemetry_to_csv():
    """Reads the SQLite database and exports to a CSV for Chapter 4."""
    print_header("EXPORTING TELEMETRY TO CSV")
    
    if not os.path.exists(DB_FILE):
        print(f"{Colors.RED}Error: Database {DB_FILE} not found.{Colors.RESET}")
        return

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get all records
        cursor.execute("SELECT id, timestamp, ip_address, target_username, status, rs, es, tier, latency_ms, honeypot_triggered FROM audit_logs ORDER BY id ASC")
        rows = cursor.fetchall()
        
        # Get column names
        headers = [description[0] for description in cursor.description]
        
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
            
        print(f"{Colors.GREEN}✓ Export Complete! Generated: {CSV_FILE}{Colors.RESET}")
        print(f"{Colors.GREEN}✓ Total records exported: {len(rows)}{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}Export failed: {e}{Colors.RESET}")
    finally:
        if 'conn' in locals():
            conn.close()

# ─────────────────────────────────────────────
# Execution
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print_header("THE DETECTION SYSTEM THESIS SIMULATOR")
    print("Ensure Uvicorn backend is running on port 8000.")
    print("Starting automated attack vectors in 3 seconds...\n")
    time.sleep(3)
    
    # Launch attacks simultaneously using threads
    t1 = threading.Thread(target=attack_sledgehammer)
    t2 = threading.Thread(target=attack_cred_stuffing)
    t3 = threading.Thread(target=attack_honeypot)
    t4 = threading.Thread(target=attack_low_and_slow)
    
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    
    # Wait for all attacks to finish
    t1.join()
    t2.join()
    t3.join()
    t4.join()
    
    print(f"\n{Colors.GREEN}✓ All attack simulations complete.{Colors.RESET}")
    
    # Give the backend a second to finish writing to SQLite
    time.sleep(1)
    
    # Dump the results
    export_telemetry_to_csv()
    
    print("\nNext Steps:")
    print("1. Open thesis_telemetry_results.csv in Excel.")
    print("2. Filter by IP '192.168.100.55' to graph the Sledgehammer attack.")
    print("3. Plot the 'rs' and 'es' columns against 'timestamp' to generate your Chapter 4 charts.")
