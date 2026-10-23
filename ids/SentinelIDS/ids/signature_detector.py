from datetime import datetime
from collections import defaultdict
import json
import time
from pathlib import Path

# ============================================================
# SENTINELIDS - MODULE 3
# SIGNATURE DETECTOR
# ============================================================

BASE = Path(__file__).resolve().parent.parent
ALERT_FOLDER = BASE / "data" / "alerts"
ALERT_FOLDER.mkdir(parents=True, exist_ok=True)
ALERT_FILE = ALERT_FOLDER / f"alerts_{time.strftime('%Y-%m-%d_%H-%M-%S')}.jsonl"

# ---------------- Trackers ---------------- #

port_tracker = defaultdict(set)
icmp_tracker = defaultdict(int)
ssh_tracker = defaultdict(int)

# ---------------- Signature Rules ---------------- #

SIGNATURE_RULES = {
    "EXCESSIVE_SYN": {
        "severity": "HIGH",
        "description": "High number of SYN packets detected."
    },
    "EXCESSIVE_RST": {
        "severity": "MEDIUM",
        "description": "High number of RST packets detected."
    },
    "HIGH_PACKET_RATE": {
        "severity": "MEDIUM",
        "description": "Unusually high packet rate detected."
    },
    "HIGH_FORWARD_RATE": {
        "severity": "MEDIUM",
        "description": "Unusually high forward packet rate detected."
    },
    "PORT_SCAN": {
        "severity": "HIGH",
        "description": "Source IP scanned multiple destination ports."
    },
    "PING_SWEEP": {
        "severity": "MEDIUM",
        "description": "Possible ICMP ping sweep detected."
    },
    "FIN_SCAN": {
        "severity": "MEDIUM",
        "description": "Possible TCP FIN scan detected."
    },
    "DNS_FLOOD": {
        "severity": "MEDIUM",
        "description": "Possible DNS flood detected."
    },
    "SSH_BRUTE_FORCE": {
        "severity": "HIGH",
        "description": "Possible SSH brute force attack detected."
    }
}


# ============================================================
# DISPLAY ALERT
# ============================================================

def display_signature_alert(alert):

    print("\n" + "=" * 65)
    print("SIGNATURE DETECTION ALERT")
    print("=" * 65)
    print("Timestamp        :", alert["timestamp"])
    print("Signature        :", alert["signature"])
    print("Severity         :", alert["severity"])
    print("Description      :", alert["description"])
    print("Source IP        :", alert["source_ip"])
    print("Destination IP   :", alert["destination_ip"])
    print("Destination Port :", alert["destination_port"])
    print("=" * 65)


# ============================================================
# SAVE ALERT
# ============================================================

def save_signature_alert(alert):

    with open(ALERT_FILE, "a") as file:
        file.write(json.dumps(alert) + "\n")


# ============================================================
# DETECT SIGNATURES
# ============================================================

def detect_signatures(features):

    alerts = []

    if not features:
        return alerts

    # Ignore ARP broadcasts (avoid false positives)
    if features.get("Protocol") == "ARP":
        return alerts

    src_ip = features.get("Source IP")
    dst_ip = features.get("Destination IP")
    dst_port = features.get("Destination Port")
    protocol = features.get("Protocol")

    # ----------------------------------------------------
    # 1. EXCESSIVE SYN
    # ----------------------------------------------------

    if (
        features.get("SYN Flag Count", 0) >= 10
        and features.get("Flow Duration", 0) <= 5
    ):

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "EXCESSIVE_SYN",
            "severity": SIGNATURE_RULES["EXCESSIVE_SYN"]["severity"],
            "description": SIGNATURE_RULES["EXCESSIVE_SYN"]["description"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port
        })

    # ----------------------------------------------------
    # 2. EXCESSIVE RST
    # ----------------------------------------------------

    if features.get("RST Flag Count", 0) >= 10:

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "EXCESSIVE_RST",
            "severity": SIGNATURE_RULES["EXCESSIVE_RST"]["severity"],
            "description": SIGNATURE_RULES["EXCESSIVE_RST"]["description"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port
        })

    # ----------------------------------------------------
    # 3. HIGH PACKET RATE
    # ----------------------------------------------------

    if features.get("Flow Packets/s", 0) >= 100:

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "HIGH_PACKET_RATE",
            "severity": SIGNATURE_RULES["HIGH_PACKET_RATE"]["severity"],
            "description": SIGNATURE_RULES["HIGH_PACKET_RATE"]["description"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port
        })

    # ----------------------------------------------------
    # 4. HIGH FORWARD RATE
    # ----------------------------------------------------

    if features.get("Fwd Packets/s", 0) >= 100:

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "HIGH_FORWARD_RATE",
            "severity": SIGNATURE_RULES["HIGH_FORWARD_RATE"]["severity"],
            "description": SIGNATURE_RULES["HIGH_FORWARD_RATE"]["description"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port
        })

    # ----------------------------------------------------
    # 5. PORT SCAN
    # ----------------------------------------------------

    if protocol == "TCP" and dst_port is not None:

        port_tracker[src_ip].add(dst_port)

        if len(port_tracker[src_ip]) >= 10:

            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "signature": "PORT_SCAN",
                "severity": SIGNATURE_RULES["PORT_SCAN"]["severity"],
                "description": SIGNATURE_RULES["PORT_SCAN"]["description"],
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port
            })

            port_tracker[src_ip].clear()

    # ----------------------------------------------------
    # 6. ICMP PING SWEEP
    # ----------------------------------------------------

    if protocol == "ICMP":

        icmp_tracker[src_ip] += 1

        if icmp_tracker[src_ip] >= 10:

            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "signature": "PING_SWEEP",
                "severity": SIGNATURE_RULES["PING_SWEEP"]["severity"],
                "description": SIGNATURE_RULES["PING_SWEEP"]["description"],
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": None
            })

            icmp_tracker[src_ip] = 0

    # ----------------------------------------------------
    # 7. FIN SCAN
    # ----------------------------------------------------

    if (
        protocol == "TCP"
        and features.get("FIN Flag Count", 0) >= 5
    ):

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "FIN_SCAN",
            "severity": SIGNATURE_RULES["FIN_SCAN"]["severity"],
            "description": SIGNATURE_RULES["FIN_SCAN"]["description"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port
        })

    # ----------------------------------------------------
    # 8. DNS FLOOD
    # ----------------------------------------------------

    if (
        protocol == "UDP"
        and dst_port == 53
        and features.get("Flow Packets/s", 0) >= 100
    ):

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "signature": "DNS_FLOOD",
            "severity": SIGNATURE_RULES["DNS_FLOOD"]["severity"],
            "description": SIGNATURE_RULES["DNS_FLOOD"]["description"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port
        })

    # ----------------------------------------------------
    # 9. SSH BRUTE FORCE
    # ----------------------------------------------------

    if protocol == "TCP" and dst_port == 22:

        ssh_tracker[src_ip] += 1

        if ssh_tracker[src_ip] >= 20:

            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "signature": "SSH_BRUTE_FORCE",
                "severity": SIGNATURE_RULES["SSH_BRUTE_FORCE"]["severity"],
                "description": SIGNATURE_RULES["SSH_BRUTE_FORCE"]["description"],
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": 22
            })

            ssh_tracker[src_ip] = 0

    return alerts


# ============================================================
# PROCESS SIGNATURES
# ============================================================

def process_signatures(features):

    alerts = detect_signatures(features)

    for alert in alerts:
    
        save_signature_alert(alert)
        
    return alerts
