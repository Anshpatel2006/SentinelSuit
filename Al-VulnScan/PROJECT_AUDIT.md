# AI-VulnScan Project Audit

## Scope and handling

The supplied `nmap.zip` was the implementation source. It contained root Python modules, a bundled virtual environment, a private `.env`, `.env.example`, and a generated `report.md`. The source modules and non-secret setup files were restored into `Al-VulnScan`; the virtual environment and generated scan report were not copied. Neither the archive's `.env` values nor the workspace `.env` values were printed or copied over. The workspace `.env` was inspected only for variable names and remains untouched.

The ZIP's `.env.example` contained a populated NVD API-key field rather than a placeholder. That value has been removed from the project template. Because the key was included in the supplied archive, revoke/rotate it at NVD. The archive's `.env` also contained a populated `NVD_API_KEY`; its value is deliberately not reproduced here. The old template referenced optional VirusTotal and Google Safe Browsing keys, but no corresponding integration existed in this project.

## Findings in the supplied implementation

| Component/location | Supplied behavior | Audit result |
|---|---|---|
| `main.py`: `extract_services`, `process_service`, `main` | Accepted both a mapping and list, called CVE/AI per service, and appended directly to one `report.md`. It did not invoke the fingerprint or evidence engines, did not select profiles interactively, and created/truncated a report before scan success. | Pipeline disconnected; fragile mixed return contract; report formats and history absent from main execution. Replaced with an explicit authorized CLI workflow and one mapping contract. |
| `scanner.py`: `validate_target`, `build_scan_arguments`, `scan_target` | DNS validation resolved names during validation; CIDR and host-count boundaries were absent. Default TCP selection expanded to all ports, used `--script=safe`, did not set a timeout, and invoked through `python-nmap`. Nmap output was converted to a host-specific mapping without raw XML. Errors returned `None`. | Scope checks, runtime bounds, XML preservation, and predictable failure status were missing. Replaced with bounded `subprocess.run(argv)`, explicit confirmation flags, and stable result mappings. |
| `cve_lookup.py`: `search_cves`, `search_cve_details` | Used NVD keyword search and returned CVE IDs or records marked `candidate`; had a timeout but no retry, rate-limit policy, cache, CPE match, or affected-version assessment. | Candidate status was correctly cautious but applicability was absent. Added bounded retry/cache and conservative CPE/version-range states. |
| `ai_analyzer.py`: `analyze_with_llm` | Used a local `ollama run` subprocess without a timeout or service/model checks. Prompt requested Linux remediation commands and an AI-generated severity score; broad exceptions returned a text error. | Could hang and blur evidence with AI speculation. Replaced by bounded local Ollama API calls, structured evidence, model checks, and advisory-only output. |
| `report_generator.py`: `append_report_md` | Only wrote a small Markdown fragment to a fixed path. | No JSON/HTML, evidence structure, scan metadata, safe non-overwrite behavior, or resilience for missing data. Replaced with Markdown/JSON/HTML generators. |
| `fingerprint_engine.py`: `fingerprint_scan` | Already preserved Nmap values and disabled HTTP probing by default; probe behavior was opt-in. | Useful implementation was retained and connected. Added confidence provenance, selected response security headers, IPv6 URL formatting, and per-host targeting for CIDR results. |
| `evidence_engine.py`: `evaluate_service`, `evaluate_scan` | Already classified version completeness, port-state uncertainty, and Nmap evidence confidence. | Useful implementation was retained and now runs in the pipeline. It does not independently verify a version. |
| `scan_storage.py`: `ScanStorage` | Already provided atomic per-scan JSON, metadata, optional XML, unique IDs, and path validation. | Retained JSON storage as the existing compatible format; connected it to the workflow, added report-location updates and corrupt-record logging. |
| `config_auditor.py` | Empty file. | No checks existed. Added evidence-only HTTP header checks; probes remain opt-in and TLS checks remain explicitly unimplemented. |
| `scan_comparator.py` | Empty file. | No comparison existed. Added scan comparison with scope/completeness limitations and no unsupported remediation claims. |
| `requirements.txt` | Listed OpenAI and python-nmap despite local Ollama and other scanner code; omitted `python-dotenv`, `packaging`, and pytest. | Replaced with direct dependencies used by the application and tests. |
| `.env.example` | Contained a populated NVD API key and unused third-party key placeholders. | Replaced with empty secret placeholder and validated configuration values. |
| Tests/docs | No test files, testing guide, architecture, security guide, or audit/plan documents. | Added sanitized fixture tests and documentation. |

## Data-flow and contract defects

- The prior scanner returned `None` on several failures and a dictionary on success; `main.py` included compatibility branches for lists and dictionaries instead of enforcing one contract.
- XML output was not preserved; therefore scan metadata, hostnames, script evidence, per-port reasons, and raw scan evidence could be lost.
- Fingerprint and evidence modules existed but were not called by the main workflow.
- The CLI used only `search_cves()` IDs, so detailed NVD metadata and applicability could not reach AI or reports.
- AI output was generated per service and requested risk scores/commands, while deterministic scan evidence and scores were not present to constrain it.
- Scan history and comparison code did not run from the CLI; configuration auditing had no implementation.
- No mocked pipeline tests existed to catch return-contract and error-path issues.

## Current implementation boundaries

The implemented rules identify only selected open clear-text service indicators. NVD records remain candidates or CPE/version matches; no exploitability proof is attempted. JSON file storage was retained instead of migrating the project to SQLite. HTTP header review is opt-in; TLS certificate/protocol checks, authenticated auditing, full CVE logical-expression evaluation, and vendor backport identification remain limitations.
