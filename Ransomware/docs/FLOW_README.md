# AI Malware Analysis Platform — Analysis Modes

## Flow

Lookup-only:
START -> Upload -> MD5/SHA1/SHA256 -> VirusTotal/MalwareBazaar ->
Risk assessment -> JSON/HTML/PDF.

Full analysis:
START -> Upload -> Hashes and threat intel -> Static -> CAPE ->
Memory features -> ML -> Risk assessment -> JSON/HTML/PDF.

Lookup-only uses:

- upload.py
- hashing.py
- threat_intel.py
- report.py

Full analysis additionally uses static analysis, CAPE, memory feature extraction,
and ML modules.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-flow.txt
```

Set API keys if desired:

```bash
cp .env.example .env
export VIRUSTOTAL_API_KEY="..."
export MALWAREBAZAAR_API_KEY="..."
```

## Run

```bash
./run_flow.sh /path/to/sample.exe
```

The API and dashboard default to lookup-only. Select full analysis in the UI to
enable static analysis and submission to the configured CAPE sandbox.

For CLI full analysis:

```bash
python -m malware_platform.pipeline.flow /path/to/sample.exe --full-analysis
```

## Outputs

`reports/` receives:
- `<sample>_final.json`
- `<sample>_final.html`
- `<sample>_final.pdf`
