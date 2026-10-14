from datetime import datetime
import json
import os


# ============================================================
# SENTINELIDS - MODULE 3
# SIGNATURE DETECTION
# ============================================================

ALERT_FILE = "/root/SentinelIDS/data/alerts.jsonl"


# ============================================================
# SIGNATURE RULES
# ============================================================

SIGNATURE_RULES = {

    "EXCESSIVE_SYN": {
        "severity": "HIGH",
        "description": "High number of SYN packets detected"
    },

    "EXCESSIVE_RST": {
        "severity": "MEDIUM",
        "description": "High number of RST packets detected"
    },

    "HIGH_PACKET_RATE": {
        "severity": "MEDIUM",
        "description": "Unusually high packet rate detected"
    },

    "HIGH_FORWARD_RATE": {
        "severity": "MEDIUM",
        "description": "Unusually high forward packet rate detected"
    }
}


# ============================================================
# SIGNATURE DETECTION
# ============================================================

def detect_signatures(features):

    if not features:
        return []

    alerts = []

    # --------------------------------------------------------
    # Signature 1: Excessive SYN
    # --------------------------------------------------------

    syn_count = features.get(
        "SYN Flag Count",
        0
    )

    flow_duration = features.get(
        "Flow Duration",
        0
    )

    if syn_count >= 10 and flow_duration <= 5:

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "EXCESSIVE_SYN",
            "severity": SIGNATURE_RULES["EXCESSIVE_SYN"]["severity"],
            "description": SIGNATURE_RULES["EXCESSIVE_SYN"]["description"],
            "source_ip": features.get("Source IP"),
            "destination_ip": features.get("Destination IP"),
            "destination_port": features.get("Destination Port")
        })


    # --------------------------------------------------------
    # Signature 2: Excessive RST
    # --------------------------------------------------------

    rst_count = features.get(
        "RST Flag Count",
        0
    )

    if rst_count >= 10:

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "EXCESSIVE_RST",
            "severity": SIGNATURE_RULES["EXCESSIVE_RST"]["severity"],
            "description": SIGNATURE_RULES["EXCESSIVE_RST"]["description"],
            "source_ip": features.get("Source IP"),
            "destination_ip": features.get("Destination IP"),
            "destination_port": features.get("Destination Port")
        })


    # --------------------------------------------------------
    # Signature 3: High packet rate
    # --------------------------------------------------------

    packet_rate = features.get(
        "Flow Packets/s",
        0
    )

    if packet_rate >= 100:

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "HIGH_PACKET_RATE",
            "severity": SIGNATURE_RULES["HIGH_PACKET_RATE"]["severity"],
            "description": SIGNATURE_RULES["HIGH_PACKET_RATE"]["description"],
            "source_ip": features.get("Source IP"),
            "destination_ip": features.get("Destination IP"),
            "destination_port": features.get("Destination Port")
        })


    # --------------------------------------------------------
    # Signature 4: High forward packet rate
    # --------------------------------------------------------

    forward_rate = features.get(
        "Fwd Packets/s",
        0
    )

    if forward_rate >= 100:

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "HIGH_FORWARD_RATE",
            "severity": SIGNATURE_RULES["HIGH_FORWARD_RATE"]["severity"],
            "description": SIGNATURE_RULES["HIGH_FORWARD_RATE"]["description"],
            "source_ip": features.get("Source IP"),
            "destination_ip": features.get("Destination IP"),
            "destination_port": features.get("Destination Port")
        })


    return alerts


# ============================================================
# DISPLAY SIGNATURE ALERT
# ============================================================

def display_signature_alert(alert):

    print()
    print("=" * 65)
    print("              SIGNATURE DETECTION ALERT")
    print("=" * 65)

    print(f"Timestamp        : {alert['timestamp']}")
    print(f"Signature        : {alert['signature']}")
    print(f"Severity         : {alert['severity']}")
    print(f"Description      : {alert['description']}")
    print(f"Source IP        : {alert['source_ip']}")
    print(f"Destination IP   : {alert['destination_ip']}")
    print(f"Destination Port : {alert['destination_port']}")

    print("=" * 65)


# ============================================================
# SAVE SIGNATURE ALERT
# ============================================================

def save_signature_alert(alert):

    os.makedirs(
        os.path.dirname(ALERT_FILE),
        exist_ok=True
    )

    with open(
        ALERT_FILE,
        "a"
    ) as file:

        file.write(
            json.dumps(alert) + "\n"
        )


# ============================================================
# PROCESS SIGNATURES
# ============================================================

def process_signatures(features):

    alerts = detect_signatures(features)

    for alert in alerts:

        # Display alert in terminal
        display_signature_alert(alert)

        # Save alert to alerts.jsonl
        save_signature_alert(alert)

    return alerts
