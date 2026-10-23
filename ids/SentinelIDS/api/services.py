import json
from pathlib import Path
from collections import Counter

BASE = Path(__file__).resolve().parent.parent

ALERT_FOLDER = BASE / "data" / "alerts"
DECISION_FOLDER = BASE / "data" / "decisions"
SCAN_FOLDER = BASE / "data" / "scans"
REPORT_FOLDER = BASE / "reports"


# ============================================================
# READ LATEST TIMESTAMPED FILE
# ============================================================

def latest_file(folder, pattern):

    files = sorted(folder.glob(pattern))

    if not files:
        return None

    return files[-1]


def read_jsonl(file_path):

    data = []

    if file_path is None or not file_path.exists():
        return data

    with open(file_path, "r") as file:

        for line in file:

            if line.strip():
                data.append(json.loads(line))

    return data


# ============================================================
# ALERTS
# ============================================================

def get_alerts():

    alert_file = latest_file(ALERT_FOLDER, "alerts_*.jsonl")

    return read_jsonl(alert_file)


def get_high_alerts():

    alerts = get_alerts()

    return [
        alert
        for alert in alerts
        if alert.get("risk_score", 0) >= 70
    ]


# ============================================================
# DECISIONS
# ============================================================

def get_decisions():

    decision_file = latest_file(DECISION_FOLDER, "decisions_*.jsonl")

    return read_jsonl(decision_file)


# ============================================================
# SCANS
# ============================================================

def get_scans():

    scan_file = latest_file(SCAN_FOLDER, "scan_results_*.jsonl")

    return read_jsonl(scan_file)


# ============================================================
# AI REPORTS
# ============================================================

def get_reports():

    reports = []

    if not REPORT_FOLDER.exists():
        return reports

    files = sorted(REPORT_FOLDER.glob("incident_*.json"))

    for file in files:

        with open(file, "r") as f:
            reports.append(json.load(f))

    reports.reverse()

    return reports


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

def get_dashboard_summary():

    alerts = get_alerts()
    scans = get_scans()
    reports = get_reports()

    severity_counter = Counter()
    attack_counter = Counter()
    protocol_counter = Counter()

    for alert in alerts:

        severity_counter[alert.get("severity", "LOW")] += 1
        attack_counter[alert.get("attack_name", "UNKNOWN")] += 1
        protocol_counter[alert.get("protocol", "OTHER")] += 1

    return {
        "total_alerts": len(alerts),

        "high_alerts": len(
            [a for a in alerts if a.get("severity") == "HIGH"]
        ),

        "critical_alerts": len(
            [a for a in alerts if a.get("severity") == "CRITICAL"]
        ),

        "scan_count": len(scans),
        "report_count": len(reports),

        "severity_distribution": dict(severity_counter),
        "attack_distribution": dict(attack_counter),
        "protocol_distribution": dict(protocol_counter)
    }


# ============================================================
# ANALYTICS DATA
# ============================================================

def get_analytics():

    alerts = get_alerts()

    attack_counter = Counter()
    severity_counter = Counter()
    protocol_counter = Counter()

    risk_scores = []

    for alert in alerts:

        attack_counter[alert.get("attack_name")] += 1
        severity_counter[alert.get("severity")] += 1
        protocol_counter[alert.get("protocol")] += 1

        risk_scores.append(alert.get("risk_score", 0))

    return {
        "attacks": attack_counter,
        "severity": severity_counter,
        "protocols": protocol_counter,
        "risk_scores": risk_scores
    }
