# Architecture

## Module Layout

```text
src/malware_platform/
├── api/              FastAPI app, routes, job store, schemas
├── analysis/         Static analysis, CAPE client, Authenticode (full mode)
├── cli/              CLI entry point (malware-analyze)
├── ingestion/        Upload validation and hashing
├── intel/            VirusTotal & MalwareBazaar lookups
├── memory/           MalMem55 Volatility extractor + plugins (full mode)
├── ml/               Random Forest engine and training (full mode)
├── pipeline/         End-to-end orchestration (flow.py)
├── reporting/        Threat-intelligence reports and risk scoring
└── config.py         Central configuration
```

## Analysis Flow

```text
INPUT
  |
  v
Upload / Validation
  |
  v
MD5 / SHA1 / SHA256
  |
  v
VirusTotal + MalwareBazaar
  |
  +---- Lookup only ------------------------------+
  |                                               |
  +---- Full mode -> Static Analysis -> CAPE      |
                                    |             |
                                    v             |
                             Memory Features      |
                                    |             |
                                    v             |
                             ML Classification    |
                                    |             |
                                    +-------------+
                                                  |
                                                  v
                                        Risk Assessment
                                                  |
                                                  v
                                         JSON / HTML / PDF
                                                  |
                                                 END
```
