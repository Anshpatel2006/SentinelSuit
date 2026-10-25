# AI Malware Analysis Platform

Malware analysis platform with two upload modes: hash lookups through VirusTotal and MalwareBazaar only, or full analysis with static inspection, CAPE sandbox, memory features, and ML classification.

## Project Structure

```
├── src/malware_platform/     # Python package
│   ├── api/                    # FastAPI REST API
│   ├── analysis/               # Static analysis, CAPE, signing
│   ├── cli/                    # CLI entry point
│   ├── ingestion/              # Upload & hashing
│   ├── intel/                  # VirusTotal & MalwareBazaar
│   ├── memory/                 # MalMem55 Volatility extractor
│   ├── ml/                     # Random Forest engine & training
│   ├── pipeline/               # End-to-end orchestration
│   └── reporting/              # Reports, IOCs, risk scoring
├── frontend/                   # React dashboard (Vite + TypeScript)
│   └── src/
│       ├── api/                # API client
│       ├── components/         # Layout & UI components
│       ├── hooks/              # React hooks
│       ├── pages/              # Route pages
│       └── types/              # TypeScript interfaces
├── scripts/                    # Shell scripts & verification
├── data/                       # Training datasets (gitignored)
├── models/                     # Trained ML models
├── yara_rules/                 # YARA rule sets
├── uploads/                    # Sample storage (gitignored)
├── reports/                    # Generated reports (gitignored)
└── docs/                       # Architecture documentation
```

Requirements and design references:

- [Software Requirements Specification](docs/SRS.md)
- [System diagrams](docs/DIAGRAMS.md)
- [Architecture overview](docs/ARCHITECTURE.md)

## Quick Start

### Backend

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
copy .env.example .env
# Set VIRUSTOTAL_API_KEY in .env

# CLI analysis
python main.py C:\path\to\sample.exe

# REST API server
malware-api
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 — the UI proxies API requests to port 8080.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | — |
| `MALWAREBAZAAR_API_KEY` | MalwareBazaar API key | — |
| `CAPE_URL` | CAPE Sandbox API URL | `http://127.0.0.1:8000` |
| `CAPE_STORAGE` | CAPE analysis storage path | `/opt/CAPEv2/storage/analyses` |
| `API_PORT` | REST API port | `8080` |
| `VOL_BINARY` | Volatility 3 binary | `vol` |
| `YARA_BINARY` | YARA scanner binary | `./yara64.exe` |

## Analysis Flow

```
Lookup only: Upload → Hash → VirusTotal + MalwareBazaar → Report
Full:        Upload → Hash → Threat Intel → Static → CAPE → Memory/ML → Report
```

The dashboard defaults to lookup-only. Full analysis is an explicit choice and submits the
sample to the configured CAPE sandbox; use it only with an isolated, trusted CAPE environment.

## Upload Limits

Uploads accept any file extension and are limited to 250 MiB.

## Security

- Never commit API keys or malware samples.
- `uploads/`, `reports/`, `logs/`, and `data/` are gitignored.
- Run CAPE and Volatility in isolated lab environments only.
