import json
import time
from pathlib import Path
from risk import severity_for_risk

BASE = Path(__file__).resolve().parent.parent

ALERT_FOLDER = BASE / "data" / "alerts"
ALERT_FOLDER.mkdir(parents=True, exist_ok=True)

RUN_TIMESTAMP = time.strftime("%Y-%m-%d_%H-%M-%S")
ALERT_FILE = ALERT_FOLDER / f"alerts_{RUN_TIMESTAMP}.jsonl"

SAVE_THRESHOLD = 70

RISK_MAPPING = {
    "EXCESSIVE_SYN": (95, "HIGH"),
    "SSH_BRUTE_FORCE": (95, "HIGH"),
    "FTP_BRUTE_FORCE": (95, "HIGH"),
    "PORT_SCAN": (90, "HIGH"),
    "PORTSCAN": (90, "HIGH"),
    "DDOS": (95, "HIGH"),
    "DOS_HULK": (85, "HIGH"),
    "DOS_GOLDENEYE": (85, "HIGH"),
    "BOT": (85, "HIGH"),
    "INFILTRATION": (90, "HIGH"),
    "ANOMALY": (70, "HIGH"),
    "HIGH_PACKET_RATE": (60, "MEDIUM"),
    "HIGH_FORWARD_RATE": (60, "MEDIUM"),
    "PING_SWEEP": (60, "MEDIUM"),
    "FIN_SCAN": (60, "MEDIUM"),
    "DNS_FLOOD": (60, "MEDIUM"),
    "BENIGN": (0, "LOW")
}


class AlertProcessor:

    def process_alert(self, features, signature_alert=None, ml_result=None):

        detection_method = None
        attack_name = "BENIGN"
        confidence = 0.0

        if signature_alert:
            detection_method = "RULE"
            attack_name = signature_alert[0]["signature"]
            confidence = 100.0

        elif (
            ml_result
            and ml_result["status"] == "SUCCESS"
            and ml_result["prediction"] != "BENIGN"
        ):
            detection_method = "ML"
            attack_name = str(ml_result["prediction"]).upper()
            confidence = ml_result["confidence"]

        else:
            return None

        risk_score, _ = RISK_MAPPING.get(attack_name, (50, "MEDIUM"))
        severity = severity_for_risk(risk_score)

        final_alert = {
            "timestamp": time.time(),
            "source_ip": features.get("Source IP"),
            "destination_ip": features.get("Destination IP"),
            "protocol": features.get("Protocol"),
            "source_port": features.get("Source Port"),
            "destination_port": features.get("Destination Port"),

            "detection_method": detection_method,
            "attack_name": attack_name,

            "risk_score": risk_score,
            "severity": severity,

            "ml_prediction": attack_name,
            "ml_confidence": confidence,

            "signature_alert": signature_alert if signature_alert else []
        }

        if risk_score >= SAVE_THRESHOLD:

            with open(ALERT_FILE, "a") as file:
                file.write(json.dumps(final_alert) + "\n")

            print(f"[ALERT SAVED] {attack_name} | {severity} | Risk {risk_score}")

        else:
            print(f"[MONITOR] {attack_name} | {severity} | Risk {risk_score}")

        return final_alert


processor = AlertProcessor()
