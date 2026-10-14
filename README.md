# SentinelSuit

Unified Cybersecurity Suite integrating AI-powered malware analysis, vulnerability scanning, intrusion detection, and phishing intelligence into a unified operational platform.

## Architecture & Included Modules

| Module | Directory | Description |
| :--- | :--- | :--- |
| **SentinelSuite** | `SentinelSuite/` | Unified composition UI and orchestration layer connecting all core security microservices. |
| **AI Malware Analysis** | `AI-Malware-Analysis-Platform/` | Advanced static/dynamic malware and ransomware analysis platform powered by YARA rules and ML heuristics. |
| **AI VulnScan** | `Al-VulnScan/` | Automated network and web vulnerability scanning and reporting engine. |
| **Intrusion Detection (IDS)** | `SentinelIDS_Project_Vidisha/` | Network Intrusion Detection System with machine-learning traffic classification and active threat mitigation. |
| **Phishing Link Analysis** | `phishing_react_app_fixed/` | Phishing domain and URL intelligence service with feature extraction and ML detection models. |

---

## Getting Started

Refer to each module's dedicated directory or the orchestration scripts inside `SentinelSuite/` to run individual services or launch the unified environment:

- **Unified Suite Orchestration**: `cd SentinelSuite && ./start.sh` or `sudo ./super-start.sh`
- **Malware Analysis Service**: `cd AI-Malware-Analysis-Platform`
- **Vulnerability Scanner**: `cd Al-VulnScan`
- **Intrusion Detection System**: `cd SentinelIDS_Project_Vidisha/SentinelIDS`
- **Phishing Detection Service**: `cd phishing_react_app_fixed/backend`
