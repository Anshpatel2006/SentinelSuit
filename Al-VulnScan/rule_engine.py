"""Deterministic, evidence-backed service exposure rules."""

from __future__ import annotations

from typing import Any

RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "NET-CLR-001",
        "name": "Telnet service exposed",
        "description": "An open Telnet service commonly transmits credentials and session data without transport encryption.",
        "services": {"telnet"},
        "severity": "high",
        "confidence": "medium",
        "remediation": "Disable Telnet where it is not required; otherwise restrict access and migrate administration to SSH.",
        "references": ["https://www.cisa.gov/secure-our-world"],
        "false_positive": "A service label is a fingerprint, not proof of the server's authentication or encryption configuration.",
    },
    {
        "rule_id": "NET-CLR-002",
        "name": "FTP service exposed",
        "description": "An open FTP service may transmit credentials and content in clear text unless protected by an appropriate secure variant.",
        "services": {"ftp"},
        "severity": "medium",
        "confidence": "low",
        "remediation": "Prefer SFTP or FTPS; if FTP is required, restrict exposure and verify encryption and authentication settings.",
        "references": ["https://www.cisa.gov/secure-our-world"],
        "false_positive": "FTP detection alone does not determine whether explicit TLS or network-layer protection is configured.",
    },
)


def evaluate_rules(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate only rules whose minimum observation is a confirmed open service."""
    if not isinstance(scan_result, dict):
        raise TypeError("scan_result must be a dictionary.")
    services = scan_result.get("services", [])
    if not isinstance(services, list):
        raise ValueError("scan_result['services'] must be a list.")

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for service in services:
        if not isinstance(service, dict) or service.get("state") != "open":
            continue
        name = str(service.get("service", "")).strip().lower()
        for rule in RULES:
            if name not in rule["services"]:
                continue
            try:
                port = int(service["port"])
            except (KeyError, TypeError, ValueError):
                continue
            host = str(service.get("host") or scan_result.get("target") or "")
            key = (host, port, rule["rule_id"])
            if key in seen:
                continue
            seen.add(key)
            evidence = [
                {
                    "source": "nmap_xml",
                    "field": "port.state",
                    "value": "open",
                    "observed_at": scan_result.get("scan_finished"),
                },
                {
                    "source": "nmap_xml",
                    "field": "port.service.name",
                    "value": name,
                    "observed_at": scan_result.get("scan_finished"),
                },
            ]
            findings.append(
                {
                    "finding_id": f"{rule['rule_id']}:{host}:{port}",
                    "rule_id": rule["rule_id"],
                    "name": rule["name"],
                    "description": rule["description"],
                    "host": host,
                    "port": port,
                    "protocol": service.get("protocol", "tcp"),
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "status": "potential",
                    "evidence_requirements": ["confirmed open port", "matching service name"],
                    "evidence": evidence,
                    "remediation": rule["remediation"],
                    "references": list(rule["references"]),
                    "false_positive_considerations": rule["false_positive"],
                    "service": dict(service),
                }
            )
    return findings


def evaluate_scan(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Add a stable deduplicated rule findings list to a scan result."""
    result = dict(scan_result)
    findings = evaluate_rules(result)
    result["findings"] = findings
    result["rule_summary"] = {"rules_evaluated": len(RULES), "findings": len(findings)}
    return result
