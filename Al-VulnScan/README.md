# AI-VulnScan

AI-VulnScan is a local, evidence-driven inventory and vulnerability-triage tool for **authorized security assessments**. It runs bounded Nmap scans, parses Nmap XML, retains observed service evidence, evaluates deterministic exposure rules, queries the NVD CVE API for candidates, and optionally requests advisory analysis from a locally running Ollama instance.

It is not an exploit framework. It does not run intrusive vulnerability scripts, execute AI-generated commands, or claim that a keyword hit proves a vulnerability.

## Features

- Explicit target/scope confirmation, strict IP/CIDR/hostname validation, CIDR and port limits.
- Quick, standard, deep, explicitly confirmed aggressive all-TCP, all-TCP-and-UDP, UDP, and comprehensive scan profiles.
- Nmap invocation through an argument list with timeout and XML output.
- Normalized host, port, state, service, version, CPE, script, and OS observations.
- Fingerprint confidence and uncertainty retained separately from observed values.
- Deterministic, evidence-backed rules for selected clear-text service exposure.
- NVD CVE 2.0 keyword/CPE candidates with conservative affected-version range evaluation.
- Optional local Ollama analysis; no automatic model downloads and no AI authority over scan/risk facts.
- Traceable explanations, deterministic 0–100 risk scores, and non-executable remediation advice.
- Markdown, JSON, and HTML reports; JSON-based scan history and conservative comparisons.
- Optional, explicitly enabled HTTP header observations. TLS certificate auditing is not currently implemented.

## Requirements

- Linux with Python 3.10 or newer.
- Nmap installed and on `PATH`.
- Internet access only for NVD lookups (optional); Ollama is local and optional.
- Do not run the application as root by default. TCP connect scans are used; UDP scans may require additional OS permissions and report limitations.

## Installation (Linux)

```bash
sudo apt update
sudo apt install nmap python3 python3-venv
cd Al-VulnScan
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The program does not replace an existing `.env`. Create one only if needed:

```bash
cp -n .env.example .env
```

Set `NVD_API_KEY` in `.env` only if you have a valid key; the key is optional. Never put credentials in `.env.example`, source, reports, or commits.

## Ollama (optional)

Install Ollama using its official instructions. Start its local service:

```bash
ollama serve
```

In another terminal, explicitly download a model you choose:

```bash
ollama pull llama3:latest
```

Configure `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, and `OLLAMA_TIMEOUT` in `.env`. The scanner does not download models. If the service or model is unavailable, deterministic scan results and reports remain available.

## Running

```bash
source .venv/bin/activate
python main.py
```

The CLI defaults to `127.0.0.1`. It displays the exact scope and profile and requires explicit authorization confirmation before sending scan traffic. CIDR scopes require a second confirmation; comprehensive, aggressive TCP, and all TCP+UDP scans require their own explicit confirmation. A one-request HTTP probe is separately opt-in. Blank custom port sets use profile defaults; when a custom TCP or UDP set is supplied, only the selected custom protocol/port sets are scanned. The all-ports profiles cannot be combined with custom ports.

### Local HTTP API

The optional backend adapter is independent of the CLI and uses the same scanner, analysis pipeline, scan history, and report generator. Start it from this module directory:

```bash
source .venv/bin/activate
python api.py --port 8765
```

It always binds to `127.0.0.1`; there is no option to expose it on a network interface. Browser CORS is restricted to exact localhost origins. Configure them as a comma-separated `AL_VULNSCAN_CORS_ORIGINS` value (default: `http://localhost:5173,http://127.0.0.1:5173`). Each configured origin must use HTTP(S) and a `localhost`, `127.0.0.1`, or `[::1]` host.

API routes:

- `GET /health` — `{"status":"ok"}`.
- `GET /profiles` — available profile IDs, names, and descriptions.
- `POST /scans` — accepts the request schema below and returns HTTP 202 with `scan_id`, `status`, `progress`, `result`, `error`, `target`, and `profile`. Every submission must contain the literal JSON boolean `authorized: true`. Multi-address CIDRs additionally require `confirm_multiple_hosts: true`; comprehensive, aggressive TCP, and all TCP+UDP profiles require their respective confirmation boolean.
- `GET /scans` — `{"scans":[...]}` history records with the same `scan_id`, `status`, `progress`, `result`, `error`, `target`, and `profile` fields; a history record's `result` is `null`, and completed results are fetched individually.
- `GET /scans/{scan_id}` — scan status and, when complete, the saved result.
- `GET /scans/{scan_id}/report?format=md|json|html` — downloads an existing generated report when present, with its matching content type and `Content-Disposition: attachment; filename="<scan_id>.<extension>"`.

The `target` value uses the CLI's existing IP, hostname, or strict CIDR validator and configured CIDR/host bounds. A strict CIDR containing more than one address needs explicit `confirm_multiple_hosts: true`; scans remain limited to one active API job at a time. The API does not enable the optional HTTP probe or AI analysis, and tests mock the scanner. Authorization remains an operator attestation, not independent verification.

POST JSON schema (required properties shown; confirmation flags are conditionally required):

```json
{
  "target": "192.0.2.0/30",
  "profile": "standard",
  "authorized": true,
  "confirm_multiple_hosts": true,
  "confirm_aggressive": false,
  "confirm_all_ports": false,
  "confirm_comprehensive": false
}
```

Confirmation fields must be literal JSON booleans when supplied. `confirm_multiple_hosts` is required and must be `true` for targets whose validated address count exceeds one. `confirm_comprehensive`, `confirm_aggressive`, and `confirm_all_ports` are required and must be `true` for their corresponding profiles. Profile IDs include `quick`, `standard`, `deep`, `aggressive`, `all_tcp_udp`, `udp`, and `comprehensive`.

Scan submission and status objects use `{"scan_id":"...","status":"queued|running|completed|partial|failed","progress":0,"result":null,"error":null,"target":"...","profile":"..."}`. Status returns a populated `result` once available. History uses `{"scans":[<status object>,...]}` and leaves `result` null so clients can fetch it from `/scans/{scan_id}`. The report route is available only after its generated file exists; `format` is exactly `md`, `json`, or `html`.

Profiles:

| Profile | Coverage |
|---|---|
| Quick Discovery | Top 100 TCP ports, light service detection |
| Standard Vulnerability Scan | Top 1,000 TCP ports, light service detection |
| Deep Scan | All TCP ports; longer duration |
| Aggressive (All TCP Ports) | All TCP ports with version intensity 7; explicit confirmation required |
| All TCP + UDP Ports | TCP and UDP ports 1–65535 with version intensity 7 and conservative `-T2` timing; separate explicit confirmation required |
| UDP Scan | Top 50 UDP ports; `open|filtered` is not confirmed open |
| Comprehensive Scan | Broader TCP inventory; separate confirmation required |

The all-port profiles increase service-probe intensity but deliberately do not enable Nmap `-A`, NSE scripts, OS detection, or traceroute. The combined TCP+UDP profile can take substantially longer than the configured scan timeout; a timed-out scan is marked partial and its errors are retained. UDP `open|filtered` states are not confirmed open, and UDP scans can require additional OS permissions; privilege elevation is never automatic.

## Risk scoring

Risk is a deterministic 0–100 project score, not a replacement for CVSS:

| Score | Category |
|---:|---|
| 0 | Informational |
| 1–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

The engine records rule severity, NVD CVSS when a vulnerable CPE/version entry matches, evidence-confidence multipliers, and applicability status. Unverified CVE candidates are capped below Critical; current NVD matches are not marked as verified exploitability. CVSS remains a separate 0–10 source score.

## Outputs, history, and comparison

- Reports: `reports/<scan-id>.md`, `.json`, and `.html`
- Scan history: `scan_history/<scan-id>/scan.json`, `metadata.json`, and optional raw `nmap.xml`
- Comparison reports: `reports/comparisons/`

Choose **compare scan history** in the CLI to compare two saved scans. Differences in scope/profile or incomplete scans are flagged; a missing finding is not treated as proof of remediation.

## Testing

```bash
python -m pytest -q
```

Tests use sanitized XML and mocked Nmap/NVD/Ollama responses. They do not perform network scans or require Internet access.

## Configuration

See `.env.example` for validated settings:

- NVD endpoint/key, request timeout, result cap, and retry count
- Ollama base URL, model, and timeout
- Scan timeout, CIDR/host limits, and custom-port count limit
- Report and scan-history directories and log level

Configuration values are validated at import/startup. Logs never include API-key values.

## Known limitations

- NVD keyword results are candidates. A CPE/version-range match is not confirmation that a target is exploitable and does not account for vendor backports, patch metadata, configuration prerequisites, or all logical combinations in complex NVD CPE trees.
- Version ordering is evaluated only when Python's packaging version parser can compare the values; unsupported version formats remain insufficient evidence.
- Product identification and headers can be spoofed. No version is inferred from a port number or HTTP header.
- The deterministic rules cover a deliberately small set of exposed clear-text service indicators, not all vulnerability classes.
- HTTP configuration checks require the opt-in HTTP request and cover selected response headers only. TLS certificate/protocol analysis and authenticated checks are not implemented.
- UDP state detection has inherent limitations and may require elevated OS permissions; elevation is not attempted automatically.
- Scan history uses atomic JSON files to preserve the existing project format; it is not encrypted and should be protected as sensitive assessment data.
- Actual live scan behavior depends on Nmap, network reachability, host firewall policy, and the user's authorization. No live scan was run during automated tests.

## Authorized use

Only scan systems and networks for which you have explicit permission. Target validation and CLI confirmations are safety controls, not proof of authorization. Review the full selected scope and potential service impact before proceeding. See [SECURITY.md](SECURITY.md).
