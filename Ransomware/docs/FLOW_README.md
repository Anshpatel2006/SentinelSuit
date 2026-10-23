# AI Malware Analysis Platform — Complete Flow

## Flow

START -> Upload -> MD5/SHA1/SHA256 -> VirusTotal/MalwareBazaar ->
Known/Unknown -> Static -> CAPE isolated Windows VM -> behavior ->
CAPE memory dump -> Volatility 3 -> MalMem2022 55-column vector ->
Random Forest -> Benign/Malware -> IOC extraction -> AI Risk ->
JSON/HTML/PDF.

## Existing project code

The original modules are retained and used:
- upload.py
- hashing.py
- threat_intel.py
- signing.py
- static_analysis.py
- cape_client.py
- cape_feature_extractor.py
- combine_features.py
- report.py
- custom_plugins/pspcid.py
- Obfuscated-MalMem2022.csv
- ransomware_detection.ipynb

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

CAPE must already be running at http://127.0.0.1:8000 and the configured
machine must be `cuckoo1`.

For memory features, CAPE must have:

```ini
memory_dump = on
```

in `/opt/CAPEv2/conf/cuckoo.conf`.

## Run

```bash
./run_flow.sh /path/to/sample.exe
```

Train/retrain the model:

```bash
./run_flow.sh /path/to/sample.exe --retrain
```

## Outputs

`reports/` receives:
- `<sample>_static.json`
- `<sample>_cape.json`
- `<sample>_malmem55.json`
- `<sample>_malmem55.csv`
- `<sample>_final.json`
- known-sample HTML/PDF when the hash is known.

## 55 features

The extractor always emits the 55 dataset columns in the same order as
`Obfuscated-MalMem2022.csv`.

Important: current Volatility 3 can reproduce many fields directly. The
legacy Volatility-2 PSXView semantics (`eprocess_pool`, `ethread_pool`,
`pspcid_list`, `session`) and the original definitions of
`malfind.uniqueInjections` and `callbacks.nanonymous` must not be replaced
with guesses. Such fields are marked unresolved and ML prediction is blocked
until the 55-column vector is complete.
