# Architecture

## Module Layout

```text
src/malware_platform/
├── api/              FastAPI app, routes, job store, schemas
├── analysis/         Static analysis, CAPE client, Authenticode
├── cli/              CLI entry point (malware-analyze)
├── ingestion/        Upload validation and hashing
├── intel/            VirusTotal & MalwareBazaar lookups
├── memory/           MalMem55 Volatility extractor + plugins
├── ml/               Random Forest engine and training
├── pipeline/         End-to-end orchestration (flow.py)
├── reporting/        Reports, IOC extraction, risk scoring
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
  +---- Known ----> Detection Report ------------------+
  |                                                     |
  +---- Unknown -> Static Analysis -> CAPE Sandbox      |
                                   |                     |
                                   v                     |
                              Behavior Report             |
                                   |                     |
                              memory.dmp                   |
                                   |                     |
                              Volatility 3                |
                                   |                     |
                             MalMem2022 55                 |
                                   |                     |
                              Random Forest                |
                                   |                     |
                         Benign / Malware                 |
                              |       |                   |
                              |       +--> IOC extraction|
                              |                           |
                              +------------+--------------+
                                           |
                                           v
                                    AI Risk Assessment
                                           |
                                           v
                                   JSON / HTML / PDF
                                           |
                                          END
```
