# Software Requirements Specification

## 1. Purpose

The AI Malware Analysis Platform offers a lookup-only workflow and an optional full-analysis workflow. Lookup-only calculates hashes, checks VirusTotal and MalwareBazaar, and generates a report. Full analysis continues through static analysis, CAPE, memory features, and ML.

This document is the baseline for implementation, review, testing, and diagram updates. Items marked **TBD** require confirmation.

## 2. Scope

### In scope

- Sample upload and validation through the API, CLI, and dashboard.
- MD5, SHA-1, and SHA-256 hashing.
- VirusTotal and MalwareBazaar hash lookups.
- Threat-intelligence risk scoring and JSON, HTML, and PDF reports.
- Optional full analysis using static analysis, CAPE, memory-feature extraction, and ML.
- FastAPI job/status endpoints and React analyst views.

### Out of scope

- Operating or securing CAPE, Volatility, or the analysis VM.
- Replacing external threat-intelligence, sandbox, memory-forensics, or YARA tools.
- Executing untrusted samples directly on the API host.

## 3. Actors and External Systems

| Actor/system | Responsibility |
| --- | --- |
| Analyst | Uploads samples, monitors jobs, and reviews reports. |
| FastAPI service | Validates requests, starts jobs, exposes status, and serves reports. |
| CLI operator | Starts analysis from the command line. |
| React dashboard | Provides upload, job, dashboard, and report views. |
| VirusTotal / MalwareBazaar | Optional hash and reputation lookup. |

## 4. Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-01 | The system shall accept and validate a submitted sample. | Must |
| FR-02 | The system shall calculate MD5, SHA-1, and SHA-256 before lookup. | Must |
| FR-03 | The system shall tolerate unavailable threat-intelligence providers and report their lookup status. | Must |
| FR-04 | Lookup-only mode shall not submit samples to CAPE or run static/ML analysis. | Must |
| FR-05 | Full mode shall support static analysis, CAPE, memory features, and ML classification. | Should |
| FR-06 | The system shall calculate risk and generate JSON, HTML, and PDF reports. | Must |
| FR-07 | The system shall persist job state and expose progress and result information. | Must |
| FR-08 | The dashboard shall support mode selection, upload, polling, and report review. | Should |

## 5. Non-functional Requirements

| ID | Requirement | Acceptance condition |
| --- | --- | --- |
| NFR-01 | Isolation | Untrusted samples execute only in an isolated CAPE lab. |
| NFR-02 | Secret handling | API keys remain in local environment configuration and outside the deliverable. |
| NFR-03 | Traceability | Each job links its hashes, stage results, model output, IOCs, and final report. |
| NFR-04 | Resilience | External-service failures produce explicit degraded status and reason. |
| NFR-05 | Reproducibility | Feature order, model artifact, threshold, and metrics stay versioned together. |
| NFR-06 | Performance | **TBD:** define API and end-to-end time targets by deployment profile. |
| NFR-07 | Retention | **TBD:** define retention, deletion, and access-control rules. |

## 6. Data and State

The system handles potentially malicious binaries, hashes, static findings, sandbox behavior, memory artifacts, ML features, IOCs, and reports. These are restricted analysis data.

The MalMem55 contract uses the exact feature names and order from `data/Obfuscated-MalMem2022.csv` and `models/malmem55_features.json`. Production model, threshold, and metrics are under `models/`.

Lookup-only state progression is:

`received -> hashing -> threat_intel -> risk_assessment -> reporting -> completed`

Full-analysis mode continues:

`threat_intel -> static_analysis -> cape -> memory_features -> classification -> reporting -> completed`

Any stage may produce a controlled `failed` or `degraded` result. Threat-intelligence providers may be unavailable; analysis still produces a report with the lookup results.

## 7. API, UI, and Verification

The API contract is defined in `src/malware_platform/api/`; the dashboard client is `frontend/src/api/client.js`. The API shall provide sample/job creation, status/progress, result retrieval, and report download where supported.

Acceptance checks:

- `pytest` passes.
- Known hashes use the early-report path.
- Lookup-only mode does not contact CAPE.
- Full mode reports unavailable CAPE stages clearly when CAPE is absent.
- Complete feature vectors reach the model; incomplete vectors are blocked.
- JSON reports contain hashes, stage status, risk/classification evidence, and available IOCs.
- The dashboard can upload, poll, and open a report.
- Secrets and generated runtime artifacts are absent from the deliverable.

## 8. Open Decisions

- Authentication and analyst roles.
- Sample/report retention and deletion policy.
- Maximum sample size and concurrent-job limits.
- CAPE timeout and retry policy.
- Production topology and observability requirements.
- Whether example reports belong in a separate evidence archive.