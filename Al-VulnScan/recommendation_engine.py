"""Evidence-linked recommendations; actions are never executed."""

from __future__ import annotations

from typing import Any


def recommend_for_finding(finding: dict[str, Any], risk: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Build remediation guidance from a rule or an NVD CVE record."""
    risk = risk or {}
    risk_category = risk.get("category", "Informational")
    priority = risk_category if risk_category in {"Low", "Medium", "High", "Critical"} else "Informational"
    remediation = finding.get("remediation")
    if remediation:
        return [
            {
                "type": "suggested_requires_verification",
                "problem": finding.get("name", "Observed service exposure"),
                "action": remediation,
                "priority": priority,
                "expected_benefit": "Reduce exposure if the observed configuration is confirmed.",
                "evidence": finding.get("evidence", []),
                "references": finding.get("references", []),
                "verification_steps": [
                    "Confirm the service owner and business requirement.",
                    "Validate the actual configuration with the system owner.",
                    "Rescan the same authorized scope using comparable settings.",
                ],
                "operational_impact": "Disabling or changing a service may interrupt dependent applications; coordinate a maintenance window.",
            }
        ]

    cve_id = finding.get("id")
    if cve_id:
        refs = [finding.get("url")] if finding.get("url") else []
        refs.extend(finding.get("references", []))
        return [
            {
                "type": "suggested_requires_verification",
                "problem": f"Candidate {cve_id}; applicability is {finding.get('match_status', 'unknown')}.",
                "action": "Check the vendor security advisory and installed package/build metadata; apply a vendor-supported fixed update only if affected.",
                "priority": priority,
                "expected_benefit": "Address the issue if the product and affected-version range are confirmed.",
                "evidence": finding.get("evidence", {}),
                "references": list(dict.fromkeys(refs)),
                "verification_steps": [
                    "Confirm vendor, product, version, and backported patches.",
                    "Compare against the official vendor advisory and NVD affected CPE data.",
                    "Verify the fixed state using package inventory and an equivalent follow-up scan.",
                ],
                "operational_impact": "Updates may require compatibility testing and a maintenance window.",
            }
        ]

    return [
        {
            "type": "general_hardening",
            "problem": finding.get("name", "Observed service"),
            "action": "Confirm the service is required and restrict network access to approved source ranges.",
            "priority": priority,
            "expected_benefit": "Reduce unnecessary exposure.",
            "evidence": finding.get("evidence", []),
            "references": finding.get("references", []),
            "verification_steps": ["Confirm with the service owner and rescan the same authorized scope."],
            "operational_impact": "Access restrictions can disrupt legitimate clients if applied without inventory review.",
        }
    ]


def generate_recommendations(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate recommendations for rule findings and NVD candidates."""
    risk_by_id = {
        item.get("finding_id"): item.get("risk", {})
        for item in scan_result.get("risk_assessments", [])
    }
    recommendations = []
    for finding in scan_result.get("findings", []):
        recommendations.extend(
            recommend_for_finding(
                finding,
                risk_by_id.get(finding.get("finding_id")),
            )
        )
    for service in scan_result.get("services", []):
        for cve in service.get("cve_candidates", []):
            risk_id = f"{cve.get('id')}:{service.get('host')}:{service.get('port')}"
            recommendations.extend(
                recommend_for_finding(cve, risk_by_id.get(risk_id))
            )
    audit = scan_result.get("configuration_audit", {})
    if isinstance(audit, dict):
        for check in audit.get("checks", []):
            if not isinstance(check, dict) or check.get("status") != "not_observed":
                continue
            recommendations.append(
                {
                    "type": "general_hardening",
                    "problem": check.get("description") or check.get("name", "HTTP header not observed"),
                    "action": check.get("guidance", "Review the observed HTTP configuration."),
                    "priority": "Low",
                    "expected_benefit": "Improve browser-side defense if the policy is appropriate for the application.",
                    "evidence": check.get("evidence", {}),
                    "references": [],
                    "verification_steps": [
                        "Review the policy with the application owner.",
                        "Check representative application routes and deployment layers.",
                    ],
                    "operational_impact": "Header changes can affect application compatibility; test before deployment.",
                }
            )
    return recommendations
