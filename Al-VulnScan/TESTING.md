# Testing

## Offline test suite

Run from the project directory:

```bash
python -m pytest -q
```

The test suite uses a sanitized Nmap XML fixture and mocks the Nmap subprocess, NVD HTTP calls, and Ollama transport. It does not require Internet access and does not initiate a real network scan.

Coverage currently includes:

- IPv4/IPv6/hostname/strict CIDR validation, CIDR limits, and TCP/UDP port parsing.
- Scan profile argv generation and refusal to scan without explicit authorization or multi-host confirmation.
- XML normalization, open versus filtered states, service version/CPE/script/OS evidence, missing fields, malformed XML, and empty/partial outputs.
- Mock Nmap subprocess contract and missing executable handling.
- Rule conditions, duplicate suppression, and confirmed-open requirements.
- CPE vendor/product and affected-version boundaries, NVD rate limiting/retries, and API failure behavior.
- Deterministic risk thresholds, candidate-score caps, explainability, and recommendations.
- HTML escaping, JSON serialization, non-overwrite reports, storage round trips, corrupt history, and incomplete comparison warnings.
- Configuration audit behavior and Ollama unavailability.
- A mocked end-to-end processing path through fingerprinting, evidence, rules, CVE candidates, risk, explanations, recommendations, and AI.

## Live integration checks

The test suite does not perform live Nmap, NVD, or Ollama requests. Before a real assessment, operators must check that Nmap is installed, that the selected profile has suitable permissions, that the exact target is authorized, and that any optional NVD/Ollama service is available.

## Results

Final offline validation in the configured Python 3.12.3 environment:

- `python -m pytest -q` — **25 passed**.
- `python -m compileall -q .` — **passed**.
- Application-module import smoke test — **passed**.
- `architecture.svg` XML parse — **passed**.
- `python -m pip check` — **no broken requirements**.
- Nmap 7.94SVN is installed in the environment, but **no live scan was run**; the scanner subprocess was tested with a mock XML response.

These results do not certify behavior against a live host, NVD availability, or an installed Ollama model.
