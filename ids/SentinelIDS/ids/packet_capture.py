from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from collections import defaultdict
from statistics import mean, stdev
import csv
import os
import json
import threading
from datetime import datetime
from pathlib import Path

from ids.signature_detector import process_signatures
from ids.anomaly_detector import detector
from processor.alert_processor import processor

BASE = Path(__file__).resolve().parent.parent
SCAN_FOLDER = BASE / "data" / "scans"
SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
ACTIVE_SCAN_ENABLED = os.getenv("IDS_ACTIVE_SCAN_ENABLED", "1").lower() not in {"0", "false", "no"}
_scan_lock = threading.Lock()
_scanned_targets = set()


def schedule_critical_scan(alert):
    """Run one bounded follow-up scan per internal target without blocking capture."""
    if not ACTIVE_SCAN_ENABLED:
        return

    target_candidates = (alert.get("destination_ip"), alert.get("source_ip"))

    def run_scan():
        try:
            from scanner.scanner import choose_target, run_nmap

            target = choose_target(*target_candidates)
            if not target:
                return

            with _scan_lock:
                if target in _scanned_targets:
                    return
                _scanned_targets.add(target)

            result = run_nmap(target)
            scan_record = {
                "timestamp": alert.get("timestamp"),
                "attack_name": alert.get("attack_name"),
                "category": "Critical live alert follow-up",
                "severity": "CRITICAL",
                "risk_score": alert.get("risk_score", 0),
                "source_ip": alert.get("source_ip"),
                "target_ip": target,
                "protocol": alert.get("protocol"),
                "destination_port": alert.get("destination_port"),
                "scan_status": result["status"],
                "scan_output": result["output"],
            }
            scan_file = SCAN_FOLDER / f"live_scans_{datetime.now():%Y-%m-%d_%H-%M-%S}.jsonl"
            with scan_file.open("a") as file:
                file.write(json.dumps(scan_record) + "\n")
            print(f"[CRITICAL SCAN] {target} -> {result['status']}")
        except Exception as error:
            print(f"[CRITICAL SCAN] failed: {error}")

    threading.Thread(target=run_scan, name="sentinelids-critical-scan", daemon=True).start()

CSV_FILE = "data/network_features.csv"

flows = defaultdict(dict)


# ---------------- Utility Functions ---------------- #

def get_protocol(packet):
    if packet.haslayer(ARP):
        return "ARP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(TCP):
        if packet[TCP].sport == 443 or packet[TCP].dport == 443:
            return "TLS"
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    return "OTHER"


def get_ports(packet):
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport

    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport

    return None, None


def get_tcp_flags(packet):
    syn = ack = fin = rst = psh = urg = 0

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        syn = int(flags.S)
        ack = int(flags.A)
        fin = int(flags.F)
        rst = int(flags.R)
        psh = int(flags.P)
        urg = int(flags.U)

    return syn, ack, fin, rst, psh, urg


def average(values):
    if not values:
        return 0
    return mean(values)


def standard(values):
    if len(values) <= 1:
        return 0
    return stdev(values)


def init_flow(timestamp):
    return {
        "start_time": timestamp,
        "last_time": timestamp,

        "fwd_packets": 0,
        "bwd_packets": 0,

        "fwd_bytes": 0,
        "bwd_bytes": 0,

        "fwd_lengths": [],
        "bwd_lengths": [],

        "flow_iat": [],

        "syn": 0,
        "ack": 0,
        "fin": 0,
        "rst": 0,
        "psh": 0,
        "urg": 0,
    }


# ---------------- Feature Extraction ---------------- #

def update_flow(packet):

    if not packet.haslayer(IP) and not packet.haslayer(ARP):
        return None

    timestamp = float(packet.time)

    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        protocol = "ARP"
        src_port = None
        dst_port = None

    else:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = get_protocol(packet)
        src_port, dst_port = get_ports(packet)

    packet_length = len(packet)

    syn, ack, fin, rst, psh, urg = get_tcp_flags(packet)

    flow_key = (src_ip, dst_ip, protocol, src_port, dst_port)

    if flow_key not in flows:
        flows[flow_key] = init_flow(timestamp)

    flow = flows[flow_key]

    flow_duration = timestamp - flow["start_time"]

    if flow_duration <= 0:
        flow_duration = 0.000001

    iat = timestamp - flow["last_time"]
    flow["flow_iat"].append(iat)
    flow["last_time"] = timestamp

    flow["fwd_packets"] += 1
    flow["fwd_bytes"] += packet_length
    flow["fwd_lengths"].append(packet_length)

    flow["syn"] += syn
    flow["ack"] += ack
    flow["fin"] += fin
    flow["rst"] += rst
    flow["psh"] += psh
    flow["urg"] += urg

    fwd_max = max(flow["fwd_lengths"])
    fwd_min = min(flow["fwd_lengths"])
    fwd_mean = average(flow["fwd_lengths"])

    if flow["bwd_lengths"]:
        bwd_max = max(flow["bwd_lengths"])
        bwd_min = min(flow["bwd_lengths"])
        bwd_mean = average(flow["bwd_lengths"])
    else:
        bwd_max = bwd_min = bwd_mean = 0

    flow_iat_mean = average(flow["flow_iat"])
    flow_iat_std = standard(flow["flow_iat"])
    flow_iat_max = max(flow["flow_iat"])
    flow_iat_min = min(flow["flow_iat"])

    all_packets = flow["fwd_lengths"] + flow["bwd_lengths"]

    packet_mean = average(all_packets)
    packet_std = standard(all_packets)
    packet_max = max(all_packets)
    packet_min = min(all_packets)

    flow_bytes_sec = (flow["fwd_bytes"] + flow["bwd_bytes"]) / flow_duration
    flow_packets_sec = (flow["fwd_packets"] + flow["bwd_packets"]) / flow_duration

    fwd_packets_sec = flow["fwd_packets"] / flow_duration
    bwd_packets_sec = flow["bwd_packets"] / flow_duration

    features = {

        "Timestamp": timestamp,

        "Source IP": src_ip,
        "Destination IP": dst_ip,

        "Protocol": protocol,

        "Source Port": src_port,
        "Destination Port": dst_port,

        "Flow Duration": round(flow_duration, 6),

        "Total Fwd Packets": flow["fwd_packets"],
        "Total Backward Packets": flow["bwd_packets"],

        "Total Length of Fwd Packets": flow["fwd_bytes"],
        "Total Length of Bwd Packets": flow["bwd_bytes"],

        "Fwd Packet Length Max": fwd_max,
        "Fwd Packet Length Min": fwd_min,
        "Fwd Packet Length Mean": round(fwd_mean, 2),

        "Bwd Packet Length Max": bwd_max,
        "Bwd Packet Length Min": bwd_min,
        "Bwd Packet Length Mean": round(bwd_mean, 2),

        "Flow Bytes/s": round(flow_bytes_sec, 2),
        "Flow Packets/s": round(flow_packets_sec, 2),

        "Flow IAT Mean": round(flow_iat_mean, 6),
        "Flow IAT Std": round(flow_iat_std, 6),
        "Flow IAT Max": round(flow_iat_max, 6),
        "Flow IAT Min": round(flow_iat_min, 6),

        "Fwd Packets/s": round(fwd_packets_sec, 2),
        "Bwd Packets/s": round(bwd_packets_sec, 2),

        "Min Packet Length": packet_min,
        "Max Packet Length": packet_max,
        "Packet Length Mean": round(packet_mean, 2),
        "Packet Length Std": round(packet_std, 2),

        "SYN Flag Count": flow["syn"],
        "RST Flag Count": flow["rst"],
        "FIN Flag Count": flow["fin"],
        "ACK Flag Count": flow["ack"],
        "PSH Flag Count": flow["psh"],
        "URG Flag Count": flow["urg"],
    }

    return features


# ---------------- Display ---------------- #

def display_features(features):

    print("\n" + "=" * 70)
    print("NETWORK FLOW FEATURES")
    print("=" * 70)

    print("Source IP       :", features["Source IP"])
    print("Destination IP  :", features["Destination IP"])
    print("Protocol        :", features["Protocol"])
    print("Source Port     :", features["Source Port"])
    print("Destination Port:", features["Destination Port"])

    print("Flow Duration   :", features["Flow Duration"])
    print("Fwd Packets     :", features["Total Fwd Packets"])
    print("Bwd Packets     :", features["Total Backward Packets"])

    print("Flow Bytes/s    :", features["Flow Bytes/s"])
    print("Flow Packets/s  :", features["Flow Packets/s"])

    print("SYN Count       :", features["SYN Flag Count"])
    print("ACK Count       :", features["ACK Flag Count"])
    print("RST Count       :", features["RST Flag Count"])
    print("=" * 70)


# ---------------- Save CSV ---------------- #

def save_features(features):

    os.makedirs("data", exist_ok=True)

    file_exists = os.path.exists(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as file:

        writer = csv.DictWriter(file, fieldnames=features.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(features)


# ---------------- Packet Pipeline ---------------- #

def packet_callback(packet):

    features = update_flow(packet)

    if features is None:
        return

    display_features(features)
    save_features(features)

    # Rule-Based Detection
    signature_alert = process_signatures(features)

    # ML runs only if no signature matched
    ml_result = {
        "status": "NOT_RUN",
        "prediction": "BENIGN",
        "confidence": 0.0
    }

    if not signature_alert:
        ml_result = detector.predict(features)

    # Send to Alert Processor
    final_alert = processor.process_alert(
        features=features,
        signature_alert=signature_alert,
        ml_result=ml_result
    )

    # Ignore benign traffic and low-risk monitoring events
    if final_alert is None:
        return

    # Print only HIGH / CRITICAL alerts
    if final_alert["risk_score"] < 70:
        return

    if final_alert["severity"] == "HIGH":
        schedule_critical_scan(final_alert)

    print("\n" + "=" * 72)
    print("                    SENTINELIDS SECURITY ALERT")
    print("=" * 72)

    print(f"Attack Name      : {final_alert['attack_name']}")
    print(f"Detection Method : {final_alert['detection_method']}")
    print(f"Source IP        : {final_alert['source_ip']}")
    print(f"Destination IP   : {final_alert['destination_ip']}")
    print(f"Protocol         : {final_alert['protocol']}")
    print(f"Destination Port : {final_alert['destination_port']}")
    print(f"Severity         : {final_alert['severity']}")
    print(f"Risk Score       : {final_alert['risk_score']} / 100")

    if final_alert["detection_method"] == "ML":
        print(f"Confidence       : {final_alert['ml_confidence']} %")

    print("=" * 72 + "\n")
    
# ---------------- Start Capture ---------------- #

def start_capture(interface="eth0"):

    print("\n========== SentinelIDS ==========")
    print("[*] Module 1 : Packet Capture")
    print("[*] Module 2 : Flow Feature Extraction")
    print("[*] Module 3 : Signature Detection")
    print("[*] Module 4 : ML Anomaly Detection")
    print("[*] Hybrid IDS Pipeline Started")
    print(f"[*] Capturing packets on {interface}")
    print("[*] Press CTRL+C to stop.\n")

    sniff(
        iface=interface,
        prn=packet_callback,
        store=False,
    )


if __name__ == "__main__":
    start_capture(os.getenv("IDS_INTERFACE", "wlp4s0"))
