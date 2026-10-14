import json
import subprocess
import socket
import ipaddress
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).resolve().parent.parent

DECISION_FOLDER = BASE / "data" / "decisions"

SCAN_FOLDER = BASE / "data" / "scans"
SCAN_FOLDER.mkdir(parents=True, exist_ok=True)

RUN_TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
SCAN_RESULT_FILE = SCAN_FOLDER / f"scan_results_{RUN_TIMESTAMP}.jsonl"

SCAN_THRESHOLD = 70


# ============================================================
# DYNAMIC NETWORK DETECTION
# ============================================================

def get_kali_ip():

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]

    finally:
        sock.close()

    return ip


def get_router_ip():

    try:
        with open("/proc/net/route") as file:

            next(file)

            for line in file:

                fields = line.strip().split()

                if fields[1] == "00000000":

                    gateway_hex = fields[2]

                    return socket.inet_ntoa(
                        bytes.fromhex(gateway_hex)[::-1]
                    )

    except Exception:
        return None

    return None


KALI_IP = get_kali_ip()
ROUTER_IP = get_router_ip()
NETWORK = ipaddress.ip_network(f"{KALI_IP}/24", strict=False)

print("Kali IP        :", KALI_IP)
print("Router IP      :", ROUTER_IP)
print("Local Network  :", NETWORK)


# ============================================================
# LOAD LATEST DECISION FILE
# ============================================================

def get_latest_decision_file():

    files = sorted(DECISION_FOLDER.glob("decisions_*.jsonl"))

    if not files:
        return None

    return files[-1]


# ============================================================
# NMAP SCANNER
# ============================================================

def run_nmap(target_ip):

    print(f"\n[SCANNER] Scanning {target_ip}")

    try:

        result = subprocess.run(
            [
                "nmap",
                "-Pn",
                "-sV",
                "-sC",
                "-T3",
                "--top-ports",
                "20",
                target_ip
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        return {
            "status": "COMPLETED",
            "output": result.stdout
        }

    except subprocess.TimeoutExpired:

        return {
            "status": "FAILED",
            "output": "Nmap scan timed out."
        }

    except Exception as error:

        return {
            "status": "FAILED",
            "output": str(error)
        }


# ============================================================
# SELECT INTERNAL TARGET
# ============================================================

def choose_target(source_ip, destination_ip):

    candidates = [source_ip, destination_ip]

    for ip in candidates:

        if ip is None:
            continue

        try:
            ip_obj = ipaddress.ip_address(ip)

        except ValueError:
            continue

        if ip == KALI_IP:
            continue

        if ROUTER_IP and ip == ROUTER_IP:
            continue

        if ip_obj not in NETWORK:
            continue

        return ip

    return None


# ============================================================
# PROCESS DECISIONS
# ============================================================

def process_decisions():

    decision_file = get_latest_decision_file()

    if decision_file is None:
        print("No decision files found.")
        return

    print("\nProcessing Decision File :", decision_file.name)

    scanned_ips = set()
    total_scans = 0

    with open(decision_file, "r") as infile, open(SCAN_RESULT_FILE, "w") as outfile:

        for line in infile:

            if not line.strip():
                continue

            decision = json.loads(line)

            risk_score = decision.get("risk_score", 0)

            if risk_score < SCAN_THRESHOLD:
                continue

            action = decision.get("action", "").upper()

            if action not in ["SCAN", "SCAN_AND_AI"]:
                continue

            source_ip = decision.get("source_ip")
            destination_ip = decision.get("destination_ip")

            target_ip = choose_target(source_ip, destination_ip)

            if target_ip is None:
                print(f"[SKIP] {source_ip} -> {destination_ip}")
                continue

            if target_ip in scanned_ips:
                continue

            scanned_ips.add(target_ip)

            scan_result = run_nmap(target_ip)

            report = {
                "timestamp": decision.get("timestamp"),
                "attack_name": decision.get("attack_name"),
                "category": decision.get("category"),
                "severity": decision.get("severity"),
                "risk_score": risk_score,

                "source_ip": source_ip,
                "target_ip": target_ip,
                "protocol": decision.get("protocol"),
                "destination_port": decision.get("destination_port"),

                "scan_status": scan_result["status"],
                "scan_output": scan_result["output"]
            }

            outfile.write(json.dumps(report) + "\n")

            total_scans += 1

            print(f"[DONE] {target_ip} ({decision.get('attack_name')})")

    print("\n" + "=" * 60)
    print("SENTINELIDS SCAN SUMMARY")
    print("=" * 60)
    print("Hosts Scanned :", total_scans)
    print("Saved File    :", SCAN_RESULT_FILE.name)
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    process_decisions()
