"""Deterministic risk scoring independent of language-model output.

Categories are Informational (0), Low (1-24), Medium (25-49),
High (50-74), and Critical (75-100).
"""

from __future__ import annotations

from typing import Any

CATEGORIES = (
    (0, "Informational"),
    (1, "Low"),
    (25, "Medium"),
    (50, "High"),
    (75, "Critical"),
)

_SEVERITY_BASE = {
    "critical": 55,
    "high": 40,
    "medium": 25,
    "low": 10,
    "informational": 0,
}


def category_for_score(score: int) -> str:
    """Map integer scores to the documented 0-100 risk categories."""
    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100.")
    return next(category for threshold, category in reversed(CATEGORIES) if score >= threshold)


def score_finding(finding: dict[str, Any], cves: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return a reproducible score and the factors used to derive it."""
    cves = cves or []
    severity = str(finding.get("severity", "informational")).lower()
    base = _SEVERITY_BASE.get(severity, 0)
    verified = finding.get("verification_status") == "verified"
    factors: list[dict[str, Any]] = [
        {"factor": "rule_severity", "value": severity, "points": base},
    ]
    score = base
    matching_cves = [
        cve for cve in cves
        if cve.get("match_status") == "version_match"
    ]
    candidate_cves = [
        cve for cve in cves
        if cve.get("match_status") in {"candidate", "product_match", "insufficient_evidence"}
    ]
    if matching_cves:
        cvss_values = [
            float(cve["cvss_score"])
            for cve in matching_cves
            if isinstance(cve.get("cvss_score"), (int, float))
            and 0 <= float(cve["cvss_score"]) <= 10
        ]
        if cvss_values:
            cvss_points = round(max(cvss_values) * 10)
            score = max(score, cvss_points)
            factors.append(
                {"factor": "NVD_CVSS_version_match", "value": max(cvss_values), "points": cvss_points}
            )
        else:
            factors.append(
                {"factor": "NVD_version_match", "value": len(matching_cves), "points": 0}
            )
    elif candidate_cves:
        score = min(score, 49)
        factors.append(
            {"factor": "unverified_CVE_candidates", "value": len(candidate_cves), "points": 0}
        )

    evidence = finding.get("confidence", "unknown")
    confidence_multiplier = {
        "high": 1.0,
        "strong": 1.0,
        "medium": 0.8,
        "weak": 0.6,
        "low": 0.5,
        "unknown": 0.25,
        "insufficient": 0.25,
    }.get(str(evidence).lower(), 0.25)
    score = round(score * confidence_multiplier)
    factors.append(
        {
            "factor": "evidence_confidence",
            "value": evidence,
            "multiplier": confidence_multiplier,
        }
    )

    # A version-range match is not proof that the vulnerable condition is
    # present. Only a separate verified status can exceed the candidate cap.
    if not verified:
        score = min(score, 74 if matching_cves else 49)
    else:
        factors.append({"factor": "verified_applicability", "value": True, "points": 10})
        score += 10

    score = max(0, min(100, int(score)))
    return {
        "score": score,
        "category": category_for_score(score),
        "factors": factors,
        "reasoning": (
            "This deterministic score combines rule severity, available NVD CVSS "
            "data, evidence confidence, and applicability status. It is not the CVSS score."
        ),
        "cvss_scores": [
            cve.get("cvss_score")
            for cve in matching_cves
            if cve.get("cvss_score") is not None
        ],
        "verified": verified,
    }


def score_scan(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Score rule findings and CVE candidates from a normalized scan."""
    scored: list[dict[str, Any]] = []
    services_by_endpoint = {
        (service.get("host"), service.get("port")): service
        for service in scan_result.get("services", [])
    }
    for finding in scan_result.get("findings", []):
        service = services_by_endpoint.get(
            (finding.get("host"), finding.get("port")),
            {},
        )
        scored.append(
            {
                "finding_id": finding.get("finding_id"),
                "name": finding.get("name", "Potential finding"),
                "host": finding.get("host", ""),
                "port": finding.get("port"),
                "service": service.get("service", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "risk": score_finding(finding),
            }
        )
    for service in scan_result.get("services", []):
        for cve in service.get("cve_candidates", []):
            finding = {
                "severity": cve.get("severity", "informational"),
                "confidence": service.get("evidence", {}).get("quality", "unknown"),
                "verification_status": (
                    "verified" if cve.get("applicability_verified") else "candidate"
                ),
            }
            scored.append(
                {
                    "finding_id": f"{cve.get('id')}:{service.get('host')}:{service.get('port')}",
                    "name": f"CVE candidate {cve.get('id')}",
                    "host": service.get("host", ""),
                    "port": service.get("port"),
                    "service": service.get("service", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "risk": score_finding(finding, [cve]),
                }
            )
    return scored
