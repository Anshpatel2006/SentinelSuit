# SentinelSuite

SentinelSuite is the shared frontend for four independent security tools. Each
module keeps its own backend, models, storage, and workflow; the dashboard
combines their live service status and available results without running scans
automatically.

| Module | Backend | Default address |
| --- | --- | --- |
| AI-VulnScan | `Al-VulnScan/api.py` | `http://127.0.0.1:8765` |
| Phishing Detection | `phising link/backend/main.py` | `http://127.0.0.1:8001` |
| Ransomware Analysis | `Ransomware/src/malware_platform/api` | `http://127.0.0.1:8080` |
| SentinelIDS | `ids/SentinelIDS/api` | `http://127.0.0.1:8002` |
| Unified frontend | `frontend/frontend` | `http://127.0.0.1:3000` |

## Run locally

Create the four Python environments using each service's own requirements, and
install the frontend dependencies once:

```bash
cd frontend/frontend
npm ci
```

Then launch the available services and UI from this directory:

```bash
cd ..
./start.sh
```

The default `all` profile also starts the local Ollama server and starts
`cape.service` if it is not already active. CAPE startup may prompt for your
sudo password. Ollama must already be installed; the launcher does not pull
models. The model defaults to `llama3:latest`; install it separately with
`ollama pull llama3:latest` if needed. Ollama and CAPE are optional: if either
is unavailable, the other suite services still attempt to start.

The launcher uses the projects' `.venv/bin/python` interpreters by default.
Override an interpreter path when needed, for example:

```bash
RANSOMWARE_PYTHON=/path/to/python ./start.sh ransomware
```

Services can also be started independently with `./start.sh ransomware`,
`phishing`, `ids`, `vulnscan`, `cape`, `ollama`, or `frontend`. Starting the
ransomware backend also checks/starts CAPE; starting `vulnscan` also checks/
starts Ollama. `OLLAMA_HOST`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, and `CAPE_URL`
can be set in the environment to override their defaults. The suite APIs and
development server bind to loopback. Ctrl+C stops child processes started by
the launcher; the CAPE system service remains running. `super-start.sh` is a
compatibility wrapper for `start.sh`.

`reset-cape.sh` is a separate, destructive maintenance script. It deletes CAPE
databases, analysis artifacts, and logs after an explicit `RESET` confirmation.
It is never run by either startup script; do not use it for ordinary startup.

Copy `frontend/.env.example` to `frontend/.env` to configure frontend API
addresses for a different setup. The launcher supplies the same defaults
directly when starting the UI.

## Safety and availability

- Startup performs no scans, sample uploads, packet capture, or CAPE data reset.
- Starting CAPE may require administrator privileges; it is only asked to start
  its system service and does not upload or analyze samples.
- SentinelIDS active follow-up scans default to disabled
  (`IDS_ACTIVE_SCAN_ENABLED=0`). Packet capture must be started separately by
  an authorized operator.
- AI-VulnScan requires explicit authorization in the UI; multi-host and
  comprehensive scans require additional confirmation. Its API binds to
  loopback and receives the Vite origin for CORS automatically.
- The phishing fetcher rejects non-public and nonstandard-port targets,
  prevents redirects, pins DNS resolution to the vetted address, and limits
  downloaded HTML. Threat-intelligence checks remain unavailable unless
  credentials are configured through the backend.
- The APIs do not provide a unified authentication layer. Keep them local;
  do not expose these loopback services to an untrusted network.
- Phishing results are not persisted by its backend, so the UI cannot show
  durable phishing scan history. Other modules report only the history their
  backend actually provides.

## Backend endpoints

- AI-VulnScan: `/health`, `/profiles`, `/scans`, `/scans/{scan_id}`, and
  `/scans/{scan_id}/report?format=md|json|html`.
- Phishing Detection: `/api/health`, `/api/model-info`, `/api/scan`, and
  `/api/report`.
- Ransomware Analysis: `/api/v1/health`, `/api/v1/analyze`, `/api/v1/jobs`,
  `/api/v1/jobs/{job_id}`, and `/api/v1/reports`.
- SentinelIDS: `/health` and `/dashboard/*` for actual IDS telemetry.

Each module page reflects its service's actual response. An unavailable service
does not block the other modules, and no placeholder scan results are shown.
