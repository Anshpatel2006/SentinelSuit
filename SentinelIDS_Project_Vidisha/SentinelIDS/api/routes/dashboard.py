from fastapi import APIRouter
from pathlib import Path
import json
from collections import Counter
from datetime import datetime
import time

router = APIRouter()

BASE = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE / "data"
REPORT_DIR = BASE / "reports"


def timestamp_sort_value(timestamp):
    if isinstance(timestamp, (int, float)):
        return float(timestamp)
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0
    return 0


SIGNATURE_RISK = {
    "EXCESSIVE_SYN": 95,
    "SSH_BRUTE_FORCE": 95,
    "FTP_BRUTE_FORCE": 95,
    "PORT_SCAN": 90,
    "PORTSCAN": 90,
    "DDOS": 95,
    "DOS_HULK": 85,
    "DOS_GOLDENEYE": 85,
    "BOT": 85,
    "INFILTRATION": 90,
    "ANOMALY": 70,
    "HIGH_PACKET_RATE": 60,
    "HIGH_FORWARD_RATE": 60,
    "PING_SWEEP": 60,
    "FIN_SCAN": 60,
    "DNS_FLOOD": 60,
}


def risk_for_alert(alert):
    risk = alert.get("risk_score")
    if risk is not None:
        try:
            return max(0, min(100, int(float(risk))))
        except (TypeError, ValueError):
            pass
    return SIGNATURE_RISK.get(str(alert.get("signature", "")).upper(), 0)


def severity_for_risk(risk):
    if risk >= 70:
        return "HIGH"
    if risk >= 30:
        return "MEDIUM"
    return "LOW"


def read_jsonl_files(folder, pattern):
    records = []
    for file_path in sorted(folder.glob(pattern)):
        if not file_path.exists():
            continue
        with open(file_path, "r") as file:
            for line in file:
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return records


def count_lines(file_path):
    if not file_path.exists():
        return 0

    with open(file_path, "r") as file:
        return sum(1 for line in file if line.strip())


def count_severity(file_path, severity):
    if not file_path.exists():
        return 0

    total = 0

    with open(file_path, "r") as file:
        for line in file:
            if not line.strip():
                continue

            decision = json.loads(line)

            if decision.get("severity") == severity:
                total += 1

    return total


@router.get("/dashboard/summary")
def dashboard_summary():

    return {
        "total_alerts": count_lines(DATA_DIR / "alerts.jsonl"),
        "high_alerts": count_severity(DATA_DIR / "decisions.jsonl", "HIGH"),
        "critical_alerts": count_severity(DATA_DIR / "decisions.jsonl", "CRITICAL"),
        "medium_alerts": count_severity(DATA_DIR / "decisions.jsonl", "MEDIUM"),
        "low_alerts": count_severity(DATA_DIR / "decisions.jsonl", "LOW"),
        "scan_count": count_lines(DATA_DIR / "scan_results.jsonl"),
        "report_count": len(list(REPORT_DIR.glob("*.json"))) if REPORT_DIR.exists() else 0,
    }
@router.get("/dashboard/recent-alerts")
def recent_alerts():
    alerts = []
    for alert_file in sorted((DATA_DIR / "alerts").glob("alerts_*.jsonl")):
        with open(alert_file, "r") as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    alert = json.loads(line)
                    risk_score = risk_for_alert(alert)
                    alerts.append({
                        "attack": alert.get("attack_name") or alert.get("signature", "Unknown Attack"),
                        "attack_name": alert.get("attack_name") or alert.get("signature", "Unknown Attack"),
                        "severity": severity_for_risk(risk_score),
                        "source_ip": alert.get("source_ip"),
                        "destination_ip": alert.get("destination_ip"),
                        "protocol": alert.get("protocol"),
                        "risk_score": risk_score,
                        "timestamp": alert.get("timestamp"),
                    })
                except (json.JSONDecodeError, OSError):
                    continue

    alerts.sort(key=lambda alert: timestamp_sort_value(alert.get("timestamp")), reverse=True)
    return alerts[:50]


@router.get("/dashboard/full-report")
def full_report():
    """Return one exportable report containing the complete IDS history."""
    alerts = read_jsonl_files(DATA_DIR / "alerts", "alerts_*.jsonl")
    decisions = read_jsonl_files(DATA_DIR / "decisions", "decisions_*.jsonl")
    scans = read_jsonl_files(DATA_DIR / "scans", "*.jsonl")
    incidents = []
    if REPORT_DIR.exists():
        for report_file in sorted(REPORT_DIR.glob("*.json")):
            try:
                with open(report_file, "r") as file:
                    incidents.append(json.load(file))
            except (json.JSONDecodeError, OSError):
                continue

    severity_counts = Counter(alert.get("severity", "LOW") for alert in alerts)
    return {
        "generated_at": time.time(),
        "summary": {
            "total_alerts": len(alerts),
            "critical_alerts": severity_counts.get("CRITICAL", 0),
            "high_alerts": severity_counts.get("HIGH", 0),
            "medium_alerts": severity_counts.get("MEDIUM", 0),
            "low_alerts": severity_counts.get("LOW", 0),
            "total_decisions": len(decisions),
            "total_scans": len(scans),
            "total_incident_reports": len(incidents),
        },
        "alerts": alerts,
        "decisions": decisions,
        "scans": scans,
        "incident_reports": incidents,
    }
    
    
@router.get("/dashboard/charts")
def dashboard_charts():

    alert_file = DATA_DIR / "alerts.jsonl"
    decision_file = DATA_DIR / "decisions.jsonl"

    attack_counter = Counter()
    severity_counter = Counter()
    hourly_counter = Counter()

    # -------- Alerts.jsonl --------

    if alert_file.exists():
        with open(alert_file, "r") as file:
            for line in file:
                if not line.strip():
                    continue

                try:
                    alert = json.loads(line)

                    attack = alert.get("attack_name", "UNKNOWN")
                    attack_counter[attack] += 1

                    ts = alert.get("timestamp")
                    if ts:
                        hour = datetime.fromtimestamp(ts).strftime("%H:00")
                        hourly_counter[hour] += 1

                except:
                    continue

    # -------- Decisions.jsonl --------

    if decision_file.exists():
        with open(decision_file, "r") as file:
            for line in file:
                if not line.strip():
                    continue

                try:
                    decision = json.loads(line)
                    severity = decision.get("severity", "LOW")
                    severity_counter[severity] += 1

                except:
                    continue

    traffic = [
        {"time": hour, "alerts": hourly_counter[hour]}
        for hour in sorted(hourly_counter.keys())
    ]

    attacks = [
        {"name": name, "value": value}
        for name, value in attack_counter.items()
    ]

    severity = [
        {"level": "LOW", "count": severity_counter["LOW"]},
        {"level": "MEDIUM", "count": severity_counter["MEDIUM"]},
        {"level": "HIGH", "count": severity_counter["HIGH"]},
        {"level": "CRITICAL", "count": severity_counter["CRITICAL"]},
    ]

    return {
        "traffic": traffic,
        "attacks": attacks,
        "severity": severity,
    }


@router.get("/dashboard/capture-status")
def capture_status():
    feature_file = DATA_DIR / "network_features.csv"
    modified_at = feature_file.stat().st_mtime if feature_file.exists() else None
    packet_count = count_lines(feature_file) - 1 if feature_file.exists() else 0
    age_seconds = round(time.time() - modified_at, 1) if modified_at else None

    return {
        "live": bool(age_seconds is not None and age_seconds <= 15),
        "interface": "configured by IDS_INTERFACE",
        "packet_count": max(packet_count, 0),
        "last_packet_at": modified_at,
        "age_seconds": age_seconds,
    }
