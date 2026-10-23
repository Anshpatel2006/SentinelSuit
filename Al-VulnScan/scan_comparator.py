"""Conservative comparison of two saved scan results."""

from __future__ import annotations

from typing import Any


def _service_key(service: dict[str, Any]) -> tuple[str, str, int | None]:
    try:
        port = int(service.get("port"))
    except (TypeError, ValueError):
        port = None
    return (
        str(service.get("host", "")),
        str(service.get("protocol", "")).lower(),
        port,
    )


def compare_scans(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare ports, fingerprints, CVEs, findings, scores, and completeness."""
    if not isinstance(previous, dict) or not isinstance(current, dict):
        raise TypeError("Both scans must be dictionaries.")
    same_scope = previous.get("scope", previous.get("target")) == current.get(
        "scope", current.get("target")
    )
    comparable = (
        same_scope
        and previous.get("status") == "completed"
        and current.get("status") == "completed"
        and previous.get("scan_type") == current.get("scan_type")
    )
    old_services = {
        _service_key(item): item
        for item in previous.get("services", [])
        if isinstance(item, dict) and item.get("state") == "open"
    }
    new_services = {
        _service_key(item): item
        for item in current.get("services", [])
        if isinstance(item, dict) and item.get("state") == "open"
    }
    old_keys, new_keys = set(old_services), set(new_services)
    service_changes = []
    for key in sorted(old_keys & new_keys):
        before, after = old_services[key], new_services[key]
        fields = ("service", "product", "version", "cpe")
        changed = {
            field: {"before": before.get(field), "after": after.get(field)}
            for field in fields
            if before.get(field) != after.get(field)
        }
        if changed:
            service_changes.append({"key": key, "changes": changed})

    def cve_ids(service_map: dict[tuple[str, str, int | None], dict[str, Any]]) -> set[str]:
        return {
            str(cve.get("id"))
            for service in service_map.values()
            for cve in service.get("cve_candidates", [])
            if cve.get("id")
        }

    old_cves, new_cves = cve_ids(old_services), cve_ids(new_services)
    old_findings = {
        finding.get("finding_id")
        for finding in previous.get("findings", [])
        if finding.get("finding_id")
    }
    new_findings = {
        finding.get("finding_id")
        for finding in current.get("findings", [])
        if finding.get("finding_id")
    }

    def risk_map(scan: dict[str, Any]) -> dict[str, int]:
        return {
            str(item.get("finding_id")): int(item.get("risk", {}).get("score", 0))
            for item in scan.get("risk_assessments", [])
            if item.get("finding_id")
        }

    old_risks, new_risks = risk_map(previous), risk_map(current)
    risk_changes = [
        {
            "finding_id": identifier,
            "before": old_risks.get(identifier),
            "after": new_risks.get(identifier),
        }
        for identifier in sorted(old_risks.keys() | new_risks.keys())
        if old_risks.get(identifier) != new_risks.get(identifier)
    ]
    confidence_changes = []
    for key in sorted(old_keys & new_keys):
        before = old_services[key].get("evidence", {}).get("quality")
        after = new_services[key].get("evidence", {}).get("quality")
        if before != after:
            confidence_changes.append({"key": key, "before": before, "after": after})

    return {
        "target": current.get("scope", current.get("target")),
        "comparable": comparable,
        "limitations": [] if comparable else [
            "Scopes, profiles, or completion status differ; absence and score changes may reflect scan configuration or incomplete coverage."
        ],
        "newly_open_ports": [dict(host=key[0], protocol=key[1], port=key[2]) for key in sorted(new_keys - old_keys)],
        "no_longer_open_ports": [dict(host=key[0], protocol=key[1], port=key[2]) for key in sorted(old_keys - new_keys)],
        "changed_fingerprints": service_changes,
        "new_cve_candidates": sorted(new_cves - old_cves),
        "cve_candidates_no_longer_observed": sorted(old_cves - new_cves),
        "new_findings": sorted(new_findings - old_findings),
        "findings_no_longer_observed": sorted(old_findings - new_findings),
        "risk_score_changes": risk_changes,
        "evidence_confidence_changes": confidence_changes,
        "remediation_progress": (
            "No remediation is claimed. A finding absent from a later scan is not proof of remediation."
        ),
    }


def format_comparison_report(comparison: dict[str, Any]) -> str:
    """Render a human-readable comparison summary."""
    lines = [
        "# Scan Comparison",
        "",
        f"- Scope: `{comparison.get('target', 'unknown')}`",
        f"- Comparable scans: {comparison.get('comparable', False)}",
        "",
        "## Changes",
        f"- Newly open ports: {len(comparison.get('newly_open_ports', []))}",
        f"- No longer open: {len(comparison.get('no_longer_open_ports', []))}",
        f"- Changed fingerprints: {len(comparison.get('changed_fingerprints', []))}",
        f"- New CVE candidates: {', '.join(comparison.get('new_cve_candidates', [])) or 'None'}",
        f"- Findings no longer observed: {len(comparison.get('findings_no_longer_observed', []))}",
        "",
        "**Remediation status:** No remediation is claimed from absence alone.",
    ]
    for limitation in comparison.get("limitations", []):
        lines.append(f"- Limitation: {limitation}")
    return "\n".join(lines) + "\n"
