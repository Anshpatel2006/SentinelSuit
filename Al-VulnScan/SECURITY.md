# Security Notes

## Authorized use only

Use AI-VulnScan only on systems and networks for which you have explicit authorization. Input validation and the CLI confirmation flow are safety controls, not proof of ownership or permission. Review and confirm the exact target/CIDR, address count, profile, ports, and optional HTTP probe before sending traffic.

The scanner does not use shell execution, does not enable vulnerability NSE scripts, does not exploit findings, and never executes AI-generated commands. TCP connect scanning is used for TCP profiles. UDP has protocol-specific reachability uncertainty; `open|filtered` is never promoted to confirmed open. Do not run the application as root by default.

## Credentials and sensitive data

- Keep `.env` out of version control. `.env.example` must contain placeholders only.
- An NVD API key was included in the supplied ZIP's environment files, including the former example file. The example was sanitized in this project. Revoke/rotate the exposed key; do not reuse it.
- The existing workspace `.env` was not overwritten, printed, or included in the updated archive.
- Reports, Nmap XML, and scan history can reveal internal hostnames, addresses, ports, software, and configuration. Store and share them accordingly.
- Logs are configured without secret values; do not add credentials or full authorization tokens to log messages.

## Evidence and AI trust boundaries

- NVD keyword results are candidates. CPE/version matches are not proof of exploitability; vendor backports and complex configuration conditions may not be represented.
- Fingerprint labels, headers, and service versions can be inaccurate or spoofed.
- Ollama text is labeled AI-assisted, can be wrong, and is not used as a CVE source, version source, or authoritative risk score.
- Recommendations are advisory. Verify vendor guidance, ownership, compatibility, and operational impact before making changes.
- Optional HTTP inspection sends one unauthenticated GET to `/` for an explicitly confirmed scope and may create normal server-side activity. It is disabled unless selected.

## Local services and dependencies

Ollama is configured as a local endpoint by default. If changing that endpoint, use a trusted service. NVD requests use HTTPS and bounded timeouts/retries. The NVD API key is sent only to the configured NVD endpoint.

## Reporting vulnerabilities

Report implementation or security concerns to the project maintainer through the repository's supported private reporting channel. Avoid attaching real scan reports or secrets to public issues.
