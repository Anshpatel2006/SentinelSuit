"""Traceable explanations generated only from scan and rule evidence."""

from __future__ import annotations

from typing import Any


def explain_finding(
    finding: dict[str, Any],
    service: dict[str, Any] | None = None,
    cves: list[dict[str, Any]] | None = None,
    risk: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a structured explanation that keeps evidence and hypotheses apart."""
    service = service or finding.get("service", {})
    cves = cves or service.get("cve_candidates", [])
    evidence = list(finding.get("evidence", []))
    service_evidence = service.get("evidence", {})
    return {
        "summary": finding.get("description") or finding.get("name", "Finding"),
        "supporting_evidence": evidence,
        "evidence_sources": sorted(
            {str(item.get("source", "unknown")) for item in evidence if isinstance(item, dict)}
        ),
        "rule_ids": [finding["rule_id"]] if finding.get("rule_id") else [],
        "cve_candidates": [
            {
                "id": cve.get("id"),
                "match_status": cve.get("match_status", "candidate"),
                "applicability_confidence": cve.get("applicability_confidence", "unknown"),
                "url": cve.get("url"),
            }
            for cve in cves
        ],
        "product_version_match_status": [
            {
                "id": cve.get("id"),
                "status": cve.get("match_status", "candidate"),
                "applicability_confidence": cve.get("applicability_confidence", "unknown"),
            }
            for cve in cves
        ],
        "evidence_confidence": finding.get(
            "confidence",
            service_evidence.get("quality", "unknown"),
        ),
        "uncertainties": [
            finding.get("false_positive_considerations", ""),
            *service_evidence.get("warnings", []),
            *[
                cve.get("applicability_note", "")
                for cve in cves
                if cve.get("match_status") != "version_match"
            ],
        ],
        "risk_factors": (risk or {}).get("factors", []),
        "risk_score": (risk or {}).get("score"),
        "next_verification_step": (
            "Confirm product and version using an authoritative inventory or vendor-supported method; "
            "then verify applicability against the vendor advisory."
            if cves
            else "Validate the service configuration and exposure with the system owner."
        ),
        "ai_interpretation": None,
    }


def explain_scan(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Attach one explanation to every rule finding and CVE candidate."""
    result = dict(scan_result)
    risk_items = result.get("risk_assessments", [])
    if not isinstance(risk_items, list):
        risk_items = []
    risks = {
        item.get("finding_id"): item.get("risk", {})
        for item in risk_items
        if isinstance(item, dict)
    }
    findings_input = result.get("findings", [])
    if not isinstance(findings_input, list):
        findings_input = []
    findings = []
    for finding in findings_input:
        if not isinstance(finding, dict):
            continue
        updated = dict(finding)
        updated["explanation"] = explain_finding(
            finding,
            cves=finding.get("cve_candidates", []),
            risk=risks.get(finding.get("finding_id")),
        )
        findings.append(updated)
    result["findings"] = findings
    risk_by_id = {
        item.get("finding_id"): item.get("risk", {})
        for item in risk_items
        if isinstance(item, dict)
    }
    services = result.get("services", [])
    if not isinstance(services, list):
        services = []
    for service in services:
        if not isinstance(service, dict):
            continue
        cves = service.get("cve_candidates", [])
        if not isinstance(cves, list):
            continue
        service_evidence = service.get("evidence", {})
        if not isinstance(service_evidence, dict):
            service_evidence = {}
        for cve in cves:
            if not isinstance(cve, dict):
                continue
            risk_id = f"{cve.get('id')}:{service.get('host')}:{service.get('port')}"
            cve["explanation"] = explain_finding(
                {"name": cve.get("id"), "confidence": service_evidence.get("quality")},
                service=service,
                cves=[cve],
                risk=risk_by_id.get(risk_id),
            )
    return result


def attach_ai_interpretation(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Attach global AI output as a clearly labeled, non-authoritative layer."""
    result = dict(scan_result)
    ai = result.get("ai_analysis", {})
    interpretation = {
        "label": "AI-assisted analysis",
        "status": ai.get("status", "not_requested"),
        "text": ai.get("analysis", "No AI interpretation was produced."),
        "authoritative": False,
    }
    for finding in result.get("findings", []):
        explanation = finding.get("explanation")
        if isinstance(explanation, dict):
            explanation["ai_interpretation"] = interpretation
    for service in result.get("services", []):
        for cve in service.get("cve_candidates", []):
            explanation = cve.get("explanation")
            if isinstance(explanation, dict):
                explanation["ai_interpretation"] = interpretation
    return result
