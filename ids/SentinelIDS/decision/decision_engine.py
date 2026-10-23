import json
from pathlib import Path
from risk import severity_for_risk

BASE = Path(__file__).resolve().parent.parent

ALERT_FOLDER = BASE / "data" / "alerts"
DECISION_FOLDER = BASE / "data" / "decisions"

ALERT_FOLDER.mkdir(parents=True, exist_ok=True)
DECISION_FOLDER.mkdir(parents=True, exist_ok=True)


# ============================================================
# DECISION ENGINE
# ============================================================

def calculate_decision(alert):

    signatures = alert.get("signature_alert", [])
    attack_name = str(alert.get("attack_name", "BENIGN")).upper()
    ml_prediction = str(alert.get("ml_prediction", "BENIGN")).upper()
    confidence = float(alert.get("ml_confidence", 0))

    severity = "LOW"
    risk_score = 0
    action = "LOG"
    category = "Normal Traffic"

    signature_names = [item.get("signature") for item in signatures]

    # ---------------- RULE DETECTIONS ----------------

    if "EXCESSIVE_SYN" in signature_names:
        severity = "HIGH"
        risk_score = 95
        category = "Denial of Service"
        action = "SCAN_AND_AI"

    elif "SSH_BRUTE_FORCE" in signature_names:
        severity = "HIGH"
        risk_score = 95
        category = "Brute Force"
        action = "SCAN_AND_AI"

    elif "FTP_BRUTE_FORCE" in signature_names:
        severity = "HIGH"
        risk_score = 95
        category = "Brute Force"
        action = "SCAN_AND_AI"

    elif "PORT_SCAN" in signature_names:
        severity = "HIGH"
        risk_score = 90
        category = "Reconnaissance"
        action = "SCAN_AND_AI"

    elif (
        "PING_SWEEP" in signature_names
        or "FIN_SCAN" in signature_names
        or "DNS_FLOOD" in signature_names
        or "HIGH_PACKET_RATE" in signature_names
        or "HIGH_FORWARD_RATE" in signature_names
    ):
        severity = "MEDIUM"
        risk_score = 60
        category = "Suspicious Network Activity"
        action = "MONITOR"

    # ---------------- ML DETECTIONS ----------------

    elif ml_prediction != "BENIGN":

        if "PORTSCAN" in ml_prediction:
            severity = "HIGH"
            risk_score = 85
            category = "Reconnaissance"
            action = "SCAN"

        elif "BOT" in ml_prediction:
            severity = "HIGH"
            risk_score = 85
            category = "Botnet Activity"
            action = "SCAN_AND_AI"

        elif "DDOS" in ml_prediction:
            severity = "HIGH"
            risk_score = 95
            category = "Distributed Denial of Service"
            action = "SCAN_AND_AI"

        elif "DOS_HULK" in ml_prediction or "DOS_GOLDENEYE" in ml_prediction:
            severity = "HIGH"
            risk_score = 85
            category = "Denial of Service"
            action = "SCAN_AND_AI"

        elif "FTP" in ml_prediction or "SSH" in ml_prediction:
            severity = "HIGH"
            risk_score = 80
            category = "Brute Force"
            action = "SCAN"

        else:
            severity = "HIGH"
            risk_score = 70
            category = "Unknown Anomaly"
            action = "SCAN"

    return {
        "timestamp": alert.get("timestamp"),
        "source_ip": alert.get("source_ip"),
        "destination_ip": alert.get("destination_ip"),
        "protocol": alert.get("protocol"),
        "source_port": alert.get("source_port"),
        "destination_port": alert.get("destination_port"),

        "attack_name": attack_name,
        "category": category,
        "severity": severity_for_risk(risk_score),
        "risk_score": risk_score,
        "action": action,

        "signature_alert": signatures,
        "ml_prediction": ml_prediction,
        "ml_confidence": confidence
    }


# ============================================================
# PROCESS LATEST ALERT FILE
# ============================================================

def process_alerts():

    print("\n========== SENTINELIDS DECISION ENGINE ==========")

    alert_files = sorted(ALERT_FOLDER.glob("alerts_*.jsonl"))

    if not alert_files:
        print("No alert files found.")
        return

    ALERT_FILE = alert_files[-1]

    print("Processing :", ALERT_FILE.name)

    with open(ALERT_FILE, "r") as infile:
        alerts = infile.readlines()

    decision_name = ALERT_FILE.name.replace("alerts_", "decisions_")
    DECISION_FILE = DECISION_FOLDER / decision_name

    processed = 0

    with open(DECISION_FILE, "w") as outfile:

        for line in alerts:

            line = line.strip()

            if line == "":
                continue

            alert = json.loads(line)

            decision = calculate_decision(alert)

            outfile.write(json.dumps(decision) + "\n")

            processed += 1

            print("-" * 60)
            print("Attack Name     :", decision["attack_name"])
            print("Source IP       :", decision["source_ip"])
            print("Destination IP  :", decision["destination_ip"])
            print("Protocol        :", decision["protocol"])
            print("Category        :", decision["category"])
            print("Severity        :", decision["severity"])
            print("Risk Score      :", decision["risk_score"])
            print("Recommended     :", decision["action"])
            print("Confidence      :", decision["ml_confidence"])

    print("-" * 60)
    print("Processed Alerts :", processed)
    print("Saved :", DECISION_FILE.name)


if __name__ == "__main__":
    process_alerts()
