# SentinelSuite — Module 3: SentinelIDS (Network Intrusion Detection System)

**Sarvajanik College of Engineering and Technology (SCET)**  
**Computer Engineering Department | B.Tech. IV, CO, SEM - VII, DIV - II**  
**Project Group No.: 10d2**  
*Project Name:* SentinelSuite — An Integrated Multi-Module Threat Detection & Prevention Platform  
*Guide:* Jaydeep Barad  

---

## 📌 Executive Overview

**SentinelIDS (Module 3)** is the real-time Network Intrusion Detection & Incident Response component of the **SentinelSuite** security ecosystem. It bridges low-level network traffic analysis with machine learning anomaly classification, Snort signature detection, automated host enumeration (bounded Nmap scanning), and AI-powered incident remediation.

### Core Capabilities
* **Live & Offline Traffic Capture:** Multi-threaded packet sniffing via **Scapy** with Berkeley Packet Filter (BPF) support, alongside offline `.pcap`/`.pcapng` forensic ingestion.
* **CICFlowMeter Feature Extraction:** Reassembles raw unidirectional packets into bidirectional 5-tuple network flows and computes **29 statistical features** (flow durations, packet lengths, inter-arrival times, flag distributions, throughput rates).
* **Hybrid Threat Decision Engine:** Fuses **Random Forest Anomaly ML** (trained on CICIDS flow metrics) with a **Snort-Compatible Rule Engine** (DPI, regex, protocol headers).
* **Dynamic Threat Severity & Risk Scoring:** Computes composite 0–100 risk scores and assigns severity tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **Automated Defensive Response Pipeline:**
  * `LOG`: Record low-risk benign/informational flows.
  * `MONITOR`: Flag suspicious hosts for connection rate escalation.
  * `SCAN`: Automatically triggers a **bounded Nmap scanner** (`-Pn -sV -sC --top-ports 20`) with hard timeouts against attacking IPs.
  * `SCAN_AND_AI`: Dispatches automated host reconnaissance and synthesizes an **AI Incident Briefing** with MITRE ATT&CK mapping and remediation playbooks.
* **Incident Reporting:** Exports high-level executive summaries and forensic evidence tables to **PDF** and **JSON** formats.
* **Unified REST API:** FastAPI backend engineered for clean integration with SentinelSuite’s React/Vite dashboard.

---

## 🏗️ Architecture & Component Mapping (From Project Presentation)

```
       [ Live Network Interface / PCAP Upload ]
                          │
                          ▼
             ┌─────────────────────────┐
             │ PacketCapture (Scapy)   │
             └────────────┬────────────┘
                          │ Packets
                          ▼
             ┌─────────────────────────┐
             │ FlowFeatureExtractor    │ ◄─── (FlowData, 29 CICFlowMeter Features)
             └────────────┬────────────┘
                          │ Bidirectional Flows
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌──────────────────┐               ┌──────────────────┐
│  RuleEngine      │               │  MLModel         │
│ (Snort Rules)    │               │ (Random Forest)  │
└───────┬──────────┘               └────────┬─────────┘
        │ Signature Matches                 │ Anomaly Confidence
        └─────────────────┬─────────────────┘
                          ▼
             ┌─────────────────────────┐
             │ DetectionEngine         │ ◄─── Hybrid Scoring & Risk Action
             │ (Hybrid Decision Engine)│
             └────────────┬────────────┘
                          │ Security Alert
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌─────────────────────────┐       ┌─────────────────────────┐
│ Bounded Nmap Scanner    │       │ AI Incident Analyzer    │
│ (-Pn -sV -sC --top-20)  │       │ (MITRE ATT&CK & Actions)│
└───────────┬─────────────┘       └───────────┬─────────────┘
            │ Scan Findings                   │ Incident Narrative
            └─────────────────┬───────────────┘
                              ▼
                ┌───────────────────────────┐
                │ AlertManager & DBManager  │
                │ (PostgreSQL / SQLite)     │
                └─────────────┬─────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌───────────────────────────┐       ┌───────────────────────────┐
│ FastAPI REST Endpoints    │       │ ReportGenerator           │
│ (To React Frontend)       │       │ (Executive PDF & JSON)    │
└───────────────────────────┘       └───────────────────────────┘
```

---

## 📂 Repository Directory Layout

```
f:\Final year project\SIDS\
├── app/
│   ├── __init__.py
│   ├── config.py                 # Configuration settings (thresholds, timeouts, paths, DB URL)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── flow_extractor.py     # FlowFeatureExtractor & FlowData (29 CICFlowMeter metrics)
│   │   ├── packet_capture.py     # PacketCapture (Scapy live sniffing + PCAP processing)
│   │   ├── rule_engine.py        # RuleEngine (Snort-compatible parser & signature matcher)
│   │   ├── ml_engine.py          # MLModel (Random Forest classifier + scaler)
│   │   ├── detection_engine.py   # DetectionEngine (Hybrid ML + Rule decision engine)
│   │   ├── nmap_scanner.py       # NmapScanner (Bounded host scanner with timeouts)
│   │   ├── ai_analyzer.py        # AIIncidentAnalyzer (MITRE ATT&CK & incident playbooks)
│   │   └── alert_manager.py      # AlertManager (Multi-channel alerting & automation)
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py             # SQLAlchemy ORM models (FlowRecord, AlertRecord, ScanRecord)
│   │   └── db_manager.py         # DatabaseManager (CRUD operations & analytical statistics)
│   ├── reporting/
│   │   ├── __init__.py
│   │   └── report_generator.py   # ReportGenerator (ReportLab PDF generation + JSON exports)
│   ├── rules/
│   │   └── snort_rules.rules     # Pre-configured Snort-style signatures
│   ├── models/
│   │   └── train_model.py        # Offline dataset training & evaluation script
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py             # FastAPI REST endpoints
│   └── main.py                   # FastAPI Application entrypoint & CORS middleware
├── captures/                     # Stored .pcap packet capture files
├── reports/                      # Generated .pdf and .json incident reports
├── test_ids.py                   # Comprehensive unit and integration test suite
├── requirements.txt              # Production Python dependencies
└── README.md                     # Comprehensive project documentation
```

---

## 📊 Class Diagram Conformance (Slide 31)

| Class Name | Key Attributes | Core Methods |
| :--- | :--- | :--- |
| **`FlowData`** | `id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `start_time`, `end_time`, `packet_count`, `byte_count` | `add_packet()`, `to_dict()` |
| **`FlowFeatureExtractor`** | `flow_timeout`, `packet_count`, `features` | `extract_features()`, `generate_features()`, `normalize_features()`, `create_flow()` |
| **`PacketCapture`** | `id`, `interface`, `filter`, `status` | `start_capture()`, `stop_capture()`, `apply_filter()`, `get_packets()`, `process_pcap()` |
| **`MLModel`** | `id`, `model_type`, `algorithm`, `model_path`, `threshold` | `load_model()`, `predict()`, `get_confidence()`, `classify()` |
| **`RuleEngine`** | `id`, `rule_set`, `rule_type`, `enabled` | `load_rules()`, `match_flow()`, `get_alert_type()`, `update_rules()` |
| **`DetectionEngine`** | `id`, `name`, `detection_type`, `threshold`, `status` | `analyze_flow()`, `combine_results()`, `classify_threat()`, `generate_alert()` |
| **`Alert`** | `id`, `timestamp`, `severity`, `attack_type`, `src_ip`, `dst_ip`, `details`, `status` | `set_severity()`, `set_status()`, `add_details()`, `to_dict()` |
| **`DatabaseManager`** | `id`, `db_type`, `connection`, `status` | `save_scan()`, `save_alert()`, `save_flow()`, `get_history()`, `get_statistics()` |
| **`ReportGenerator`** | `id`, `report_type`, `format`, `template_path` | `generate_report()`, `create_pdf()`, `create_json()`, `get_statistics()` |
| **`AlertManager`** | `id`, `notification_type`, `channels`, `enabled` | `send_alert()`, `send_email()`, `send_notification()`, `update_config()` |
| **`NmapScanner`** | `timeout`, `nmap_path`, `TOP_20_PORTS` | `run_scan()`, `_run_native_nmap()`, `_run_socket_fallback()` |
| **`AIIncidentAnalyzer`**| `ATTACK_KNOWLEDGE_BASE`, `api_key` | `generate_incident_summary()` |

---

## 🚀 REST API Reference (FastAPI Backend)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/packet/start` | Starts background live packet sniffing on specified interface with BPF filter. |
| `POST` | `/api/v1/packet/stop` | Stops packet capture, flushes active flows, and saves `.pcap` capture file. |
| `GET` | `/api/v1/packet/status` | Real-time capture state, packet counters, and recent flow telemetry. |
| `GET` | `/api/v1/packet/interfaces` | Enumerate available host network adapters. |
| `POST` | `/api/v1/packet/upload` | Upload `.pcap`/`.pcapng` files for offline deep flow analysis. |
| `GET` | `/api/v1/ids/alerts` | Paginated security alerts with severity and keyword filtering. |
| `GET` | `/api/v1/ids/alerts/{id}` | Detailed alert record including raw flow features and rule SID matches. |
| `PATCH`| `/api/v1/ids/alerts/{id}/status`| Analyst triage update (`NEW`, `INVESTIGATING`, `RESOLVED`, `DISMISSED`). |
| `GET` | `/api/v1/ids/stats` | Unified dashboard metrics: severity breakdown, top attackers, alert rate. |
| `POST` | `/api/v1/ids/report/generate`| Compiles all alerts and statistical telemetry into PDF and JSON reports. |
| `GET` | `/api/v1/ids/report/download/{id}` | Downloads the compiled PDF or JSON artifact. |
| `POST` | `/api/v1/ids/scan` | Manually trigger a bounded Nmap scan against a suspicious IP address. |
| `POST` | `/api/v1/ids/ai/summary` | Generate on-demand AI threat narrative for an alert. |

---

## 🛠️ Installation & Setup

### 1. Prerequisites
* Python 3.10+
* (Optional) **Npcap** (on Windows) or `libpcap` (on Linux) for live promiscuous sniffing.
* (Optional) **Nmap** installed in system PATH for native OS and service fingerprinting.

### 2. Environment Setup
```bash
# Clone or navigate to the repository directory
cd "f:\Final year project\SIDS"

# Create and activate a Python virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Verify Components
Execute the built-in test suite to confirm end-to-end functionality:
```bash
python test_ids.py
```

### 4. Start the SentinelIDS Backend Server
```bash
# Launch FastAPI server with Uvicorn
python -m app.main
```
The server will bind to `http://localhost:8002` (Swagger UI available at `http://localhost:8002/docs`).

---

## 🔗 Integration with SentinelSuite React Frontend

The SentinelIDS backend includes permissive CORS configuration out-of-the-box. In the React client (`Vite`), configure the environment variable:

```env
VITE_IDS_API_URL=http://localhost:8002/api/v1
```

All responses conform to the JSON contracts shown in Slide 29, 30, and 36 of the project presentation.
