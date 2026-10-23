from pathlib import Path
from ai.groq_client import generate_report
from datetime import datetime
import json

BASE = Path(__file__).resolve().parent.parent

DECISION_FOLDER = BASE / "data" / "decisions"
SCAN_FOLDER = BASE / "data" / "scans"

REPORT_FOLDER = BASE / "reports"
REPORT_FOLDER.mkdir(parents=True, exist_ok=True)

AI_REPORT_FILE = BASE / "data" / "ai_reports.jsonl"


# ============================================================
# LOAD LATEST DECISION FILE
# ============================================================

def get_latest_decision_file():

    files = sorted(DECISION_FOLDER.glob("decisions_*.jsonl"))

    if not files:
        return None

    return files[-1]


# ============================================================
# LOAD NMAP SCAN RESULTS
# ============================================================

def load_scan_results():

    scans = {}

    files = sorted(SCAN_FOLDER.glob("scan_results_*.jsonl"))

    if not files:
        return scans

    latest_scan = files[-1]

    print("Using Scan File :", latest_scan.name)

    with open(latest_scan, "r") as file:

        for line in file:

            if not line.strip():
                continue

            scan = json.loads(line)

            scans[scan["target_ip"]] = scan

    return scans


# ============================================================
# BUILD GROQ PROMPT
# ============================================================

def build_prompt(incident):

    return f"""
You are a Senior SOC Analyst.

Analyze this SentinelIDS security incident using ONLY the supplied evidence.

Return ONLY valid JSON.

{{
  "executive_summary":"",
  "attack_type":"",
  "severity":"",
  "risk_score":0,
  "mitre_attack":{{
      "technique_id":"",
      "technique_name":"",
      "tactic":""
  }},
  "network_analysis":{{
      "traffic_observation":""
  }},
  "impact_analysis":"",
  "recommended_actions":[],
  "soc_conclusion":""
}}

INCIDENT DATA

Attack Name: {incident.get("attack_name")}
Category: {incident.get("category")}
Severity: {incident.get("severity")}
Risk Score: {incident.get("risk_score")}
Protocol: {incident.get("protocol")}
Source IP: {incident.get("source_ip")}
Target IP: {incident.get("destination_ip")}
Destination Port: {incident.get("destination_port")}
Action: {incident.get("action")}

Signature Alerts:
{json.dumps(incident.get("signature_alert", []), indent=2)}

ML Prediction:
{incident.get("ml_prediction")}

ML Confidence:
{incident.get("ml_confidence")}

Nmap Scan Output:
{incident.get("scan_output")}
"""


# ============================================================
# AI ANALYSIS PIPELINE
# ============================================================

def process_ai_analysis():

    decision_file = get_latest_decision_file()

    if decision_file is None:
        print("No decision files found.")
        return

    print(f"Processing Decision File : {decision_file.name}")

    scan_results = load_scan_results()

    reports = []
    processed_incidents = set()

    with open(decision_file, "r") as infile:

        for line in infile:

            if not line.strip():
                continue

            incident = json.loads(line)

            action = incident.get("action", "LOG")

            if action not in ["SCAN", "SCAN_AND_AI"]:
                continue

            target_ip = incident.get("destination_ip")
            attack_name = incident.get("attack_name", "UNKNOWN")

            incident_key = (
                target_ip,
                attack_name
            )

            if incident_key in processed_incidents:
                continue

            processed_incidents.add(incident_key)

            if target_ip in scan_results:
                incident["scan_output"] = scan_results[target_ip]["scan_output"]
            else:
                incident["scan_output"] = "No Nmap scan performed."

            print("=" * 65)
            print("SENTINELIDS AI INCIDENT ANALYSIS")
            print("Attack   :", attack_name)
            print("Target   :", target_ip)
            print("Severity :", incident.get("severity"))
            print("=" * 65)

            prompt = build_prompt(incident)

            try:

                response = generate_report(prompt)

                raw_path = BASE / "data" / "raw_ai_response.txt"

                with open(raw_path, "w") as raw:
                    raw.write(str(response))

                cleaned = str(response).strip()

                if cleaned.startswith("```"):
                    cleaned = cleaned.replace("```json", "")
                    cleaned = cleaned.replace("```", "").strip()

                start = cleaned.find("{")
                end = cleaned.rfind("}")

                cleaned = cleaned[start:end + 1]

                analysis = json.loads(cleaned)

            except Exception as e:

                print("Groq Parsing Error :", e)

                analysis = {
                    "executive_summary": "AI analysis could not be generated.",
                    "attack_type": attack_name,
                    "severity": incident.get("severity"),
                    "risk_score": incident.get("risk_score"),
                    "mitre_attack": {},
                    "network_analysis": {},
                    "impact_analysis": "",
                    "recommended_actions": [],
                    "soc_conclusion": "Refer to raw_ai_response.txt."
                }

            report = {
                "timestamp": incident.get("timestamp"),
                "attack_name": attack_name,
                "category": incident.get("category"),
                "source_ip": incident.get("source_ip"),
                "destination_ip": target_ip,
                "protocol": incident.get("protocol"),
                "severity": incident.get("severity"),
                "risk_score": incident.get("risk_score"),
                "action": incident.get("action"),
                "ml_prediction": incident.get("ml_prediction"),
                "ml_confidence": incident.get("ml_confidence"),
                "analysis": analysis
            }

            reports.append(report)

            report_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")

            report_file = REPORT_FOLDER / (
                f"incident_{report_time}_{attack_name}_{target_ip}.json"
            )

            with open(report_file, "w") as outfile:
                json.dump(report, outfile, indent=4)

            print("Saved :", report_file.name)

    with open(AI_REPORT_FILE, "w") as outfile:
        json.dump(reports, outfile, indent=4)

    print("\n" + "=" * 65)
    print("AI Threat Analysis Completed Successfully")
    print("Reports Generated :", len(reports))
    print("Reports Folder    :", REPORT_FOLDER)
    print("=" * 65)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    process_ai_analysis()
