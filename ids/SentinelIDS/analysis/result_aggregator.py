import json
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
NETWORK_FILE = BASE / "data" / "network_features.csv"
ALERT_FILE = BASE / "data" / "alerts.jsonl"
DECISION_FILE = BASE / "data" / "decisions.jsonl"
SCAN_FILE = BASE / "data" / "scan_results.jsonl"
OUTPUT_FILE = BASE / "data" / "aggregated_results.jsonl"


def read_last_json(file_path):

    if not file_path.exists():
        return {}

    latest = {}

    with open(file_path, "r") as f:
        for line in f:
            if line.strip():
                latest = json.loads(line)

    return latest


def read_latest_network():
    if not NETWORK_FILE.exists():
        return {}
    df = pd.read_csv(NETWORK_FILE, on_bad_lines="skip", engine="python")
    if df.empty:
        return {}
    row = df.iloc[-1]
    return {
        "source_ip": str(row.get("Source IP", "")),
        "destination_ip": str(row.get("Destination IP", "")),
        "protocol": str(row.get("Protocol", "")),
        "source_port": int(row.get("Source Port", 0)),
        "destination_port": int(row.get("Destination Port", 0)),
        "flow_duration": float(row.get("Flow Duration", 0)),
        "total_fwd_packets": int(row.get("Total Fwd Packets", 0)),
        "total_backward_packets": int(row.get("Total Backward Packets", 0)),
        "total_fwd_bytes": int(row.get("Total Fwd Bytes", 0)),
        "total_bwd_bytes": int(row.get("Total Bwd Bytes", 0)),
        "flow_bytes_per_sec": float(row.get("Flow Bytes/s", 0)),
        "flow_packets_per_sec": float(row.get("Flow Packets/s", 0)),
        "flow_iat_mean": float(row.get("Flow IAT Mean", 0)),
        "flow_iat_std": float(row.get("Flow IAT Std", 0)),
        "flow_iat_max": float(row.get("Flow IAT Max", 0)),
        "flow_iat_min": float(row.get("Flow IAT Min", 0)),
        "packet_length_mean": float(row.get("Packet Length Mean", 0)),
        "packet_length_std": float(row.get("Packet Length Std", 0)),
        "min_packet_length": float(row.get("Min Packet Length", 0)),
        "max_packet_length": float(row.get("Max Packet Length", 0)),
        "syn_flag_count": int(row.get("SYN Flag Count", 0)),
        "ack_flag_count": int(row.get("ACK Flag Count", 0)),
        "fin_flag_count": int(row.get("FIN Flag Count", 0)),
        "rst_flag_count": int(row.get("RST Flag Count", 0)),
        "psh_flag_count": int(row.get("PSH Flag Count", 0)),
        "urg_flag_count": int(row.get("URG Flag Count", 0)),
    }

import re

def parse_nmap_scan(scan):

    output = scan.get("scan_output", "")

    ports = []

    for line in output.splitlines():

        match = re.match(
            r"(\d+)\/tcp\s+(open|filtered|closed)\s+([^\s]+)(.*)",
            line
        )

        if match:
            ports.append({
                "port": int(match.group(1)),
                "state": match.group(2),
                "service": match.group(3),
                "version": match.group(4).strip()
            })

    host_status = "UP" if "Host is up" in output else "DOWN"

    return {
        "host_status": host_status,
        "total_open_ports": len(ports),
        "open_ports": ports
    }
    
def aggregate_results():
    network = read_latest_network()
    alert = read_last_json(ALERT_FILE)
    decision = read_last_json(DECISION_FILE)
    scan = read_last_json(SCAN_FILE)
    scan_info = parse_nmap_scan(scan)

    incident = {
        "timestamp": alert.get("timestamp"),
        "source_ip": network.get("source_ip"),
        # Target IP from Nmap scan, otherwise network traffic
        "target_ip": (
            scan.get("target_ip")
            or scan.get("ip")
            or scan.get("host")
            or network.get("destination_ip")
        ),
        # Alert information (works with different alert formats)
        "signature": (
            alert.get("signature")
            or alert.get("attack_type")
            or alert.get("type")
            or "UNKNOWN_ATTACK"
        ),
        "severity": (alert.get("severity") or alert.get("level") or "MEDIUM"),
        "description": (
            alert.get("description")
            or alert.get("message")
            or "No description available."
        ),
        # Decision Engine
        "risk_score": (
            decision.get("risk_score") or decision.get("Risk Score") or 40
        ),
        "action": (decision.get("action") or decision.get("Action") or "MONITOR"),
        # Live traffic features
        "flow_features": {
            "protocol": network.get("protocol"),
            "source_port": network.get("source_port"),
            "destination_port": network.get("destination_port"),
            "flow_duration": network.get("flow_duration"),
            "total_fwd_packets": network.get("total_fwd_packets"),
            "total_backward_packets": network.get("total_backward_packets"),
            "total_fwd_bytes": network.get("total_fwd_bytes"),
            "total_bwd_bytes": network.get("total_bwd_bytes"),
            "flow_bytes_per_sec": network.get("flow_bytes_per_sec"),
            "flow_packets_per_sec": network.get("flow_packets_per_sec"),
            "flow_iat_mean": network.get("flow_iat_mean"),
            "flow_iat_std": network.get("flow_iat_std"),
            "flow_iat_max": network.get("flow_iat_max"),
            "flow_iat_min": network.get("flow_iat_min"),
            "packet_length_mean": network.get("packet_length_mean"),
            "packet_length_std": network.get("packet_length_std"),
            "min_packet_length": network.get("min_packet_length"),
            "max_packet_length": network.get("max_packet_length"),
            "syn_flag_count": network.get("syn_flag_count"),
            "ack_flag_count": network.get("ack_flag_count"),
            "fin_flag_count": network.get("fin_flag_count"),
            "rst_flag_count": network.get("rst_flag_count"),
            "psh_flag_count": network.get("psh_flag_count"),
            "urg_flag_count": network.get("urg_flag_count"),
        },
        # Scanner results
        "host_status": scan_info["host_status"],
	"os_detection": "Unknown",
	"total_open_ports": scan_info["total_open_ports"],
	"open_ports": scan_info["open_ports"]
    }

    with open(OUTPUT_FILE, "w") as out:
        out.write(json.dumps(incident, indent=2))

    print("=" * 50)
    print("SentinelIDS Incident Aggregated Successfully")
    print("Source IP  :", incident.get("source_ip"))
    print("Target IP  :", incident.get("target_ip"))
    print("Signature  :", incident.get("signature"))
    print("Severity   :", incident.get("severity"))
    print("Risk Score :", incident.get("risk_score"))
    print("Action     :", incident.get("action"))
    print("Open Ports :", incident.get("total_open_ports"))
    print("Saved To   :", OUTPUT_FILE)
    print("=" * 50)


if __name__ == "__main__":
    aggregate_results()

