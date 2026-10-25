# System Diagrams

These Mermaid diagrams describe the current platform boundary and are the visual companion to `docs/SRS.md`.

## System Context

```mermaid
flowchart LR
    analyst[Analyst] --> ui[React dashboard]
    operator[CLI operator] --> cli[CLI]
    ui --> api[FastAPI API]
    cli --> pipeline[Analysis pipeline]
    api --> pipeline
    pipeline --> vt[VirusTotal]
    pipeline --> mb[MalwareBazaar]
    pipeline --> reports[JSON HTML PDF reports]
    api --> reports
```

## End-to-End Activity

```mermaid
flowchart TD
    start([Sample received]) --> validate[Validate and store]
    validate --> hash[Compute MD5 SHA-1 SHA-256]
    hash --> intel[Threat-intelligence lookup]
    intel --> risk[Calculate intelligence-based risk]
    risk --> output[Generate JSON HTML PDF]
    intel -->|Full analysis selected| static[Static analysis]
    static --> cape[Submit to configured CAPE]
    cape --> memory[Extract memory features]
    memory --> ml[Run ML when features are complete]
    ml --> output
    output --> finish([Report available])
```

## Analysis Sequence

```mermaid
sequenceDiagram
    actor Analyst
    participant UI as Dashboard or CLI
    participant API as FastAPI
    participant P as Pipeline
    participant TI as Threat Intel
    participant CAPE as CAPE
    participant R as Reporting

    Analyst->>UI: Submit sample
    UI->>API: Create analysis job
    API->>P: Validate, hash, and start job
    P->>TI: Query hashes
    TI-->>P: Lookup results
    alt Lookup-only mode
        P->>R: Calculate risk and build report
    else Full-analysis mode
        P->>P: Run static analysis
        P->>CAPE: Submit sample to configured sandbox
        CAPE-->>P: Behavior and memory results
        P->>P: Extract memory features and classify
        P->>R: Calculate risk and build full report
    end
    R-->>API: Persist report and job result
    API-->>UI: Status and report link
    UI-->>Analyst: Display analysis result
```

## Deployment View

```mermaid
flowchart TB
    browser[Analyst browser] --> frontend[Frontend host]
    frontend --> api[FastAPI service]
    api --> storage[(Samples and reports)]
    api --> providers[External intelligence APIs]
```

## Report Data Model

```mermaid
erDiagram
    ANALYSIS_JOB ||--|| SAMPLE : analyzes
    ANALYSIS_JOB ||--o{ STAGE_RESULT : contains
    ANALYSIS_JOB ||--|| FINAL_REPORT : produces
    FINAL_REPORT ||--o{ IOC : includes
    FINAL_REPORT ||--o| ML_RESULT : contains
    SAMPLE {
        string sample_id PK
        string sha256
        string sha1
        string md5
        string file_type
    }
    ANALYSIS_JOB {
        string job_id PK
        string status
        datetime created_at
    }
    STAGE_RESULT {
        string stage_result_id PK
        string stage
        string status
        string artifact_path
    }
    FINAL_REPORT {
        string report_id PK
        string risk_level
        string report_path
    }
    IOC {
        string ioc_id PK
        string type
        string value
    }
    ML_RESULT {
        string model_version
        string label
        float confidence
    }
```

Update these diagrams when pipeline stages, trust boundaries, persistence contracts, or report fields change.