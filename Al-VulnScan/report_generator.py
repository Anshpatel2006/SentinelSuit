"""Safe Markdown, JSON, and HTML report generation."""

from __future__ import annotations

import html
import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any

from config import REPORT_OUTPUT_DIR

logger = logging.getLogger(__name__)


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _messages(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _safe_scan_id(value: str | None) -> str:
    if value and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
        return value
    return uuid.uuid4().hex


def _markdown(scan: dict[str, Any]) -> str:
    lines = [
        "# AI-VulnScan Assessment Report",
        "",
        f"- **Scan ID:** `{scan.get('scan_id', 'not assigned')}`",
        f"- **Target scope:** `{scan.get('scope', scan.get('target', 'unknown'))}`",
        f"- **Profile:** {scan.get('scan_type', 'unknown')}",
        f"- **Status:** {scan.get('status', 'unknown')}",
        f"- **Authorization:** operator-attested={bool(scan.get('authorization_attested'))} (not independently verified)",
        f"- **Started:** {scan.get('scan_started', 'unknown')}",
        f"- **Finished:** {scan.get('scan_finished', 'unknown')}",
        f"- **Nmap version:** {scan.get('nmap_version') or 'unknown'}",
        f"- **Nmap exit code:** {scan.get('nmap_exit_code', 'unknown')}",
        "",
        "> CVE keyword and CPE records are candidates. A version-range match does not prove exploitability or account for vendor backports.",
        "",
        "## Observed hosts and ports",
        "",
        "| Host | Port | State | Service | Product/version |",
        "|---|---:|---|---|---|",
    ]
    services = _records(scan.get("services"))
    for service in services:
        label = " ".join(str(service.get(key, "")) for key in ("product", "version")).strip()
        lines.append(
            f"| {service.get('host', '')} | {service.get('port', '')}/{service.get('protocol', '')} "
            f"| {service.get('state', 'unknown')} | {service.get('service', '')} | {label} |"
        )
        for script in _records(service.get("scripts")):
            lines.append(
                f"  - Nmap script `{script.get('id', '')}` evidence: {script.get('output', '')}"
            )
    hosts = _records(scan.get("hosts"))
    host_lines = [
        f"- `{host.get('address', '')}` — {host.get('state', 'unknown')}; "
        f"hostnames: {', '.join(host.get('hostnames', [])) or 'none'}; "
        f"OS observations: {json.dumps(host.get('os', []), ensure_ascii=True)}"
        for host in hosts
    ]
    if not host_lines:
        host_lines.append("No host records.")
    lines.extend(
        [
            "",
            "## Discovered hosts",
            "",
            *host_lines,
        ]
    )
    lines.extend(["", "## Potential findings", ""])
    findings = _records(scan.get("findings"))
    if not findings:
        lines.append("No rule-based potential findings were produced from the collected evidence.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('name', 'Finding')} ({finding.get('severity', 'unknown')})",
                "",
                str(finding.get("description", "")),
                "",
                f"- Status: **{finding.get('status', 'potential')}**",
                f"- Evidence confidence: {finding.get('confidence', 'unknown')}",
                f"- Evidence: `{json.dumps(finding.get('evidence', []), ensure_ascii=True)}`",
                f"- Limitations: {finding.get('false_positive_considerations', 'None recorded')}",
            ]
        )
        if finding.get("explanation"):
            lines.append(f"- Explanation: `{json.dumps(finding['explanation'], ensure_ascii=True)}`")
        lines.append("")
    lines.extend(["## NVD CVE candidates", ""])
    has_cves = False
    for service in services:
        for cve in _records(service.get("cve_candidates")):
            has_cves = True
            lines.append(
                f"- **{cve.get('id', 'Unknown CVE')}** — {cve.get('match_status', 'candidate')} "
                f"(applicability confidence: {cve.get('applicability_confidence', 'unknown')}); "
                f"CVSS {cve.get('cvss_score', 'unknown')}; "
                f"[NVD record]({cve.get('url', '')})"
            )
            if cve.get("description"):
                lines.append(f"  - {cve['description']}")
    if not has_cves:
        lines.append("No CVE candidates were returned or lookup was unavailable.")
    lines.extend(["", "## Configuration audit", ""])
    checks = _records(_mapping(scan.get("configuration_audit")).get("checks"))
    if not checks:
        lines.append("No HTTP configuration checks were completed; active probing is opt-in.")
    for check in checks:
        lines.append(f"- {check.get('check_id')}: {check.get('status')} — {check.get('interpretation')}")
    lines.extend(["", "## Deterministic risk assessments", ""])
    for assessment in _records(scan.get("risk_assessments")):
        risk = _mapping(assessment.get("risk"))
        lines.append(
            f"- {assessment.get('name')}: **{risk.get('score', 0)}/100 "
            f"({risk.get('category', 'Informational')})** — {risk.get('reasoning', '')}"
        )
        lines.append(f"  - Factors: `{json.dumps(risk.get('factors', []), ensure_ascii=True)}`")
    if not scan.get("risk_assessments"):
        lines.append("No risk assessments were generated.")
    lines.extend(["", "## AI-assisted analysis", ""])
    ai = _mapping(scan.get("ai_analysis"))
    lines.append(
        str(ai.get("analysis", "AI analysis was unavailable or not requested."))
        if ai
        else "AI analysis was unavailable or not requested."
    )
    lines.append("")
    lines.append("AI output is advisory and does not override scanner observations or deterministic scoring.")
    lines.extend(["", "## Recommendations", ""])
    for recommendation in _records(scan.get("recommendations")):
        lines.append(
            f"- **{recommendation.get('priority', 'Informational')}** — "
            f"{recommendation.get('problem', '')}: {recommendation.get('action', '')}"
        )
        if recommendation.get("references"):
            references = _messages(recommendation.get("references"))
            lines.append(f"  - References: {', '.join(map(str, references))}")
        lines.append(f"  - Impact: {recommendation.get('operational_impact', 'Review before changes.')}")
    if not scan.get("recommendations"):
        lines.append("No recommendations were generated.")
    lines.extend(["", "## Errors and limitations", ""])
    errors = _messages(scan.get("errors"))
    if scan.get("nmap_stderr"):
        errors.append(f"Nmap stderr: {scan['nmap_stderr']}")
    lines.extend([f"- {error}" for error in errors] if errors else ["- No scan errors were recorded."])
    lines.append("- A scan is not proof of authorization, absence of vulnerabilities, or exploitability.")
    return "\n".join(lines) + "\n"


def _html_report(scan: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""), quote=True)

    host_rows = "".join(
        f"<li>{esc(host.get('address'))}: {esc(host.get('state'))} "
        f"({esc(', '.join(host.get('hostnames', [])))}) "
        f"OS: {esc(json.dumps(host.get('os', []), ensure_ascii=True))}</li>"
        for host in _records(scan.get("hosts"))
    ) or "<li>No host records</li>"
    service_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('host'))}</td><td>{esc(item.get('port'))}/{esc(item.get('protocol'))}</td>"
        f"<td>{esc(item.get('state'))}</td><td>{esc(item.get('service'))}</td>"
        f"<td>{esc(item.get('product'))} {esc(item.get('version'))}</td>"
        f"<td>{esc(_mapping(item.get('evidence')).get('quality', 'unknown'))}</td>"
        f"<td><pre>{esc(json.dumps(item.get('scripts', []), ensure_ascii=True))}</pre></td></tr>"
        for item in _records(scan.get("services"))
    ) or "<tr><td colspan='7'>No service records</td></tr>"
    findings = "".join(
        f"<article><h3>{esc(item.get('name'))}</h3><p>{esc(item.get('description'))}</p>"
        f"<p>Status: {esc(item.get('status'))}; confidence: {esc(item.get('confidence'))}</p>"
        f"<pre>{esc(json.dumps(item.get('evidence', []), ensure_ascii=True, indent=2))}</pre>"
        f"<pre>{esc(json.dumps(item.get('explanation', {}), ensure_ascii=True, indent=2))}</pre></article>"
        for item in _records(scan.get("findings"))
    ) or "<p>No rule-based potential findings.</p>"
    cve_items = [
        (service, cve)
        for service in _records(scan.get("services"))
        for cve in _records(service.get("cve_candidates"))
    ]
    cve_rows = "".join(
        "<tr>"
        f"<td><a href='https://nvd.nist.gov/vuln/detail/{esc(cve.get('id'))}'>{esc(cve.get('id'))}</a></td>"
        f"<td>{esc(cve.get('match_status', 'candidate'))} "
        f"({esc(cve.get('applicability_confidence', 'unknown'))})</td>"
        f"<td>{esc(cve.get('cvss_score'))} / {esc(cve.get('severity'))}</td>"
        f"<td>{esc(service.get('host'))}:{esc(service.get('port'))}</td>"
        f"<td>{esc(cve.get('description'))}</td></tr>"
        for service, cve in cve_items
    ) or "<tr><td colspan='5'>No CVE candidates</td></tr>"
    def render_risk(item: dict[str, Any]) -> str:
        risk = _mapping(item.get("risk"))
        return (
            "<tr>"
            f"<td>{esc(item.get('name'))}</td><td>{esc(risk.get('score'))}/100</td>"
            f"<td>{esc(risk.get('category'))}</td>"
            f"<td><pre>{esc(json.dumps(risk.get('factors', []), ensure_ascii=True))}</pre></td></tr>"
        )

    risk_rows = "".join(
        render_risk(item) for item in _records(scan.get("risk_assessments"))
    ) or "<tr><td colspan='4'>No risk assessments</td></tr>"
    audit = _mapping(scan.get("configuration_audit"))
    audit_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('check_id'))}</td><td>{esc(item.get('name'))}</td>"
        f"<td>{esc(item.get('status'))}</td><td>{esc(item.get('interpretation'))}</td></tr>"
        for item in _records(audit.get("checks"))
    ) or "<tr><td colspan='4'>No configuration checks completed</td></tr>"
    recommendations = "".join(
        "<article>"
        f"<h3>{esc(item.get('priority'))} — {esc(item.get('problem'))}</h3>"
        f"<p>{esc(item.get('action'))}</p>"
        f"<p>Expected benefit: {esc(item.get('expected_benefit'))}</p>"
        f"<p>Operational impact: {esc(item.get('operational_impact'))}</p>"
        f"<pre>{esc(json.dumps(item.get('verification_steps', []), ensure_ascii=True, indent=2))}</pre>"
        f"<pre>{esc(json.dumps(item.get('references', []), ensure_ascii=True, indent=2))}</pre>"
        "</article>"
        for item in _records(scan.get("recommendations"))
    ) or "<p>No recommendations generated.</p>"
    error_items = _messages(scan.get("errors"))
    if scan.get("nmap_stderr"):
        error_items.append(f"Nmap stderr: {scan['nmap_stderr']}")
    errors = "".join(f"<li>{esc(error)}</li>" for error in error_items) or "<li>None recorded</li>"
    ai = _mapping(scan.get("ai_analysis"))
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>AI-VulnScan Report</title><style>"
        "body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#142033}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #9aa8bb;padding:.5rem;text-align:left}"
        "article{border-left:4px solid #0891b2;padding:.5rem 1rem;margin:1rem 0;background:#f4f8fb}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "th{background:#e8f1f8}section{margin:1.6rem 0}</style></head><body>"
        f"<h1>AI-VulnScan Assessment Report</h1><p>Scan ID: {esc(scan.get('scan_id'))} | "
        f"Scope: {esc(scan.get('scope', scan.get('target')))} | "
        f"Profile: {esc(scan.get('scan_type'))} | Status: {esc(scan.get('status'))} | "
        f"Nmap: {esc(scan.get('nmap_version') or 'unknown')} | "
        f"Exit code: {esc(scan.get('nmap_exit_code'))} | "
        f"Authorization attested: {esc(bool(scan.get('authorization_attested')))} (not independently verified)</p>"
        f"<p>Started: {esc(scan.get('scan_started'))} | Finished: {esc(scan.get('scan_finished'))}</p>"
        "<p><strong>Candidate CVEs and AI analysis are not proof of vulnerability.</strong></p>"
        f"<section><h2>Discovered hosts</h2><ul>{host_rows}</ul></section>"
        "<section><h2>Observed services</h2><table><thead><tr><th>Host</th><th>Port</th><th>State</th>"
        "<th>Service</th><th>Product/version</th><th>Evidence confidence</th><th>Nmap script evidence</th>"
        "</tr></thead><tbody>"
        f"{service_rows}</tbody></table></section>"
        f"<section><h2>Potential findings and explanations</h2>{findings}</section>"
        "<section><h2>NVD CVE candidates</h2><table><thead><tr><th>ID</th><th>Status</th>"
        "<th>CVSS/severity</th><th>Service</th><th>Description</th></tr></thead><tbody>"
        f"{cve_rows}</tbody></table></section>"
        "<section><h2>Configuration audit evidence</h2><table><thead><tr><th>Check</th><th>Name</th>"
        "<th>Status</th><th>Interpretation</th></tr></thead><tbody>"
        f"{audit_rows}</tbody></table></section>"
        "<section><h2>Deterministic risk assessments</h2><table><thead><tr><th>Item</th><th>Score</th>"
        "<th>Category</th><th>Factors</th></tr></thead><tbody>"
        f"{risk_rows}</tbody></table></section>"
        f"<section><h2>AI-assisted analysis ({esc(ai.get('status', 'unavailable'))})</h2>"
        f"<p>{esc(ai.get('analysis', 'Unavailable or not requested.'))}</p>"
        "<p>AI output is advisory; deterministic evidence and risk scoring are separate.</p></section>"
        f"<section><h2>Recommendations</h2>{recommendations}</section>"
        f"<section><h2>Errors and skipped checks</h2><ul>{errors}</ul>"
        f"<p>{esc(_mapping(audit.get('summary')).get('not_run', ''))}</p></section>"
        "</body></html>"
    )


def generate_reports(
    scan_result: dict[str, Any],
    output_dir: str | Path | None = None,
    scan_id: str | None = None,
) -> dict[str, str]:
    """Write non-overwriting Markdown, JSON, and HTML reports."""
    if not isinstance(scan_result, dict):
        raise TypeError("scan_result must be a dictionary.")
    directory = Path(output_dir) if output_dir is not None else REPORT_OUTPUT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    identifier = _safe_scan_id(scan_id or scan_result.get("scan_id"))
    result = dict(scan_result)
    result["scan_id"] = identifier
    paths = {
        "markdown": directory / f"{identifier}.md",
        "json": directory / f"{identifier}.json",
        "html": directory / f"{identifier}.html",
    }
    existing = [path for path in paths.values() if path.exists()]
    if existing:
        raise FileExistsError(f"Refusing to overwrite report file: {existing[0]}")
    payloads = {
        "markdown": _markdown(result),
        "json": json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        "html": _html_report(result),
    }
    for format_name, path in paths.items():
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(payloads[format_name])
        except OSError:
            logger.exception("Could not write %s report to %s", format_name, path)
            raise
    return {key: str(path) for key, path in paths.items()}


def append_report_md(service: dict[str, Any], cves: list[Any], ai_text: str) -> None:
    """Legacy compatibility function; writes a minimal standalone Markdown report."""
    content = _markdown(
        {
            "target": service.get("host", "unknown"),
            "status": "partial",
            "services": [service],
            "findings": [],
            "recommendations": [],
            "errors": [],
            "ai_analysis": {"analysis": ai_text},
        }
    )
    for cve in cves:
        content += f"\n- CVE candidate: {html.escape(str(cve))}\n"
    path = REPORT_OUTPUT_DIR / "legacy-report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(content)
