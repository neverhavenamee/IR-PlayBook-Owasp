#!/usr/bin/env python3
"""
IR Playbook Metrics Calculator
Đo lường MTTD, MTTR, Containment Accuracy, Evidence Completeness
"""

import json
from datetime import datetime, timedelta

class IRMetrics:
    def __init__(self):
        self.results = {}

    def calculate_mttd(self, attack_start: str, detection_time: str) -> dict:
        """
        Mean Time to Detect (MTTD)
        = Detection Time - Attack Start Time
        """
        t_attack = datetime.fromisoformat(attack_start)
        t_detect = datetime.fromisoformat(detection_time)
        mttd = (t_detect - t_attack).total_seconds()

        return {
            "metric": "MTTD (Mean Time to Detect)",
            "attack_start": attack_start,
            "detection_time": detection_time,
            "mttd_seconds": mttd,
            "mttd_minutes": round(mttd / 60, 2),
            "benchmark_ibm_days": 204,
            "benchmark_ibm_hours": 204 * 24,
            "improvement_percentage": round(
                (1 - mttd / (204 * 24 * 3600)) * 100, 2
            ),
            "target_met": mttd < (204 * 24 * 3600 * 0.5)  # 50% reduction
        }

    def calculate_mttr(self, detection_time: str, containment_time: str,
                       recovery_time: str) -> dict:
        """
        Mean Time to Respond (MTTR)
        = Recovery Time - Detection Time
        """
        t_detect = datetime.fromisoformat(detection_time)
        t_contain = datetime.fromisoformat(containment_time)
        t_recover = datetime.fromisoformat(recovery_time)

        time_to_contain = (t_contain - t_detect).total_seconds()
        time_to_recover = (t_recover - t_detect).total_seconds()

        return {
            "metric": "MTTR (Mean Time to Respond)",
            "detection_time": detection_time,
            "containment_time": containment_time,
            "recovery_time": recovery_time,
            "time_to_contain_seconds": time_to_contain,
            "time_to_contain_minutes": round(time_to_contain / 60, 2),
            "time_to_recover_seconds": time_to_recover,
            "time_to_recover_minutes": round(time_to_recover / 60, 2),
            "benchmark_ibm_days": 73,
            "improvement_percentage": round(
                (1 - time_to_recover / (73 * 24 * 3600)) * 100, 2
            ),
            "target_met": time_to_recover < (73 * 24 * 3600 * 0.5)
        }

    def calculate_containment_accuracy(self, total_actions: int,
                                        correct_actions: int) -> dict:
        """
        Containment Accuracy
        = Correct containment actions / Total containment actions
        """
        accuracy = (correct_actions / total_actions * 100) if total_actions > 0 else 0

        return {
            "metric": "Containment Accuracy",
            "total_actions": total_actions,
            "correct_actions": correct_actions,
            "incorrect_actions": total_actions - correct_actions,
            "accuracy_percentage": round(accuracy, 2),
            "target": 70,
            "target_met": accuracy >= 70
        }

    def calculate_evidence_completeness(self, checklist: dict) -> dict:
        """
        Evidence Completeness
        = Collected evidence items / Total required items
        """
        total = len(checklist)
        collected = sum(1 for v in checklist.values() if v)
        completeness = (collected / total * 100) if total > 0 else 0

        return {
            "metric": "Evidence Completeness",
            "total_required": total,
            "collected": collected,
            "missing": [k for k, v in checklist.items() if not v],
            "completeness_percentage": round(completeness, 2),
            "target": 75,
            "target_met": completeness >= 75
        }

    def calculate_root_cause_identified(self, scenarios: list) -> dict:
        """
        Root Cause Identification Rate
        = Scenarios with root cause identified / Total scenarios
        """
        total = len(scenarios)
        identified = sum(1 for s in scenarios if s.get("root_cause_found"))
        rate = (identified / total * 100) if total > 0 else 0

        return {
            "metric": "Root Cause Identification Rate",
            "total_scenarios": total,
            "root_causes_found": identified,
            "rate_percentage": round(rate, 2),
            "target": 70,
            "target_met": rate >= 70
        }

    def generate_report(self, incident_data: dict) -> dict:
        """Generate complete evaluation report"""
        report = {
            "incident_id": incident_data["incident_id"],
            "vulnerability_type": incident_data["vulnerability_type"],
            "playbook_id": incident_data["playbook_id"],
            "evaluation_date": datetime.now().isoformat(),
            "metrics": {}
        }

        # Calculate all metrics
        report["metrics"]["mttd"] = self.calculate_mttd(
            incident_data["attack_start"],
            incident_data["detection_time"]
        )

        report["metrics"]["mttr"] = self.calculate_mttr(
            incident_data["detection_time"],
            incident_data["containment_time"],
            incident_data["recovery_time"]
        )

        report["metrics"]["containment_accuracy"] = self.calculate_containment_accuracy(
            incident_data["total_containment_actions"],
            incident_data["correct_containment_actions"]
        )

        report["metrics"]["evidence_completeness"] = self.calculate_evidence_completeness(
            incident_data["evidence_checklist"]
        )

        # Summary
        metrics_met = sum(1 for m in report["metrics"].values()
                         if m.get("target_met"))
        total_metrics = len(report["metrics"])

        report["summary"] = {
            "targets_met": f"{metrics_met}/{total_metrics}",
            "overall_pass": metrics_met == total_metrics,
            "recommendations": []
        }

        for name, metric in report["metrics"].items():
            if not metric.get("target_met"):
                report["summary"]["recommendations"].append(
                    f"Improve {name}: current value below target"
                )

        return report


# ===== EXAMPLE USAGE =====
if __name__ == "__main__":
    # Dữ liệu mẫu từ 1 lần test playbook
    test_data = {
        "incident_id": "INC-20260307-001",
        "vulnerability_type": "SQL Injection",
        "playbook_id": "PB-001",
        "attack_start": "2026-03-07T10:00:00",
        "detection_time": "2026-03-07T10:05:30",    # Detected in 5.5 minutes
        "containment_time": "2026-03-07T10:15:00",  # Contained in 15 minutes
        "recovery_time": "2026-03-07T11:00:00",     # Recovered in 1 hour
        "total_containment_actions": 5,
        "correct_containment_actions": 4,
        "evidence_checklist": {
            "web_server_access_log": True,
            "web_server_error_log": True,
            "application_log": True,
            "database_query_log": True,
            "wazuh_alerts": True,
            "network_capture": False,
            "session_data": True,
            "vulnerable_source_code": True
        }
    }

    calculator = IRMetrics()
    report = calculator.generate_report(test_data)

    print(json.dumps(report, indent=2))

    # Save report
    with open("evaluation/test-results/sqli-eval-001.json", "w") as f:
        json.dump(report, f, indent=2)