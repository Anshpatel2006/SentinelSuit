"""Connect deterministic scan analysis stages without making AI authoritative."""

from __future__ import annotations

import logging
from typing import Any

from ai_analyzer import analyze_scan
from config_auditor import audit_configurations
from cve_lookup import NVDLookupError, lookup_service_cves
from evidence_engine import evaluate_scan as evaluate_evidence
from explainability_engine import attach_ai_interpretation, explain_scan
from fingerprint_engine import fingerprint_scan
from recommendation_engine import generate_recommendations
from risk_engine import score_scan
from rule_engine import evaluate_scan as evaluate_rules

logger = logging.getLogger(__name__)


def analyze_scan_result(
    scan_result: dict[str, Any],
    *,
    enable_http_probe: bool = False,
    include_ai: bool = True,
) -> dict[str, Any]:
    """Enrich normalized Nmap results through fingerprint, CVE, and reporting stages."""
    if not isinstance(scan_result, dict):
        raise TypeError("scan_result must be a dictionary.")
    result = dict(scan_result)
    if not isinstance(result.get("errors"), list):
        result["errors"] = []
        logger.warning("Invalid scan errors field; initialized an empty error list.")
    raw_services = result.get("services", [])
    if not isinstance(raw_services, list):
        result["errors"].append("Invalid scanner contract: services must be a list.")
        result["services"] = []
    else:
        valid_services = [item for item in raw_services if isinstance(item, dict)]
        if len(valid_services) != len(raw_services):
            result["errors"].append(
                "Invalid scanner contract: non-object service records were excluded."
            )
            logger.error("Excluded non-object entries from scan services.")
        result["services"] = valid_services
    try:
        result = fingerprint_scan(result, enable_http_probe=enable_http_probe)
    except (TypeError, ValueError, OSError) as exc:
        logger.exception("Service fingerprinting failed.")
        result["errors"].append(f"Fingerprinting failed: {exc}")

    try:
        result = evaluate_rules(result)
    except (TypeError, ValueError, KeyError) as exc:
        logger.exception("Rule evaluation failed.")
        result["errors"].append(f"Rule evaluation failed: {exc}")
        result["findings"] = []

    try:
        result = evaluate_evidence(result)
    except (TypeError, ValueError, KeyError) as exc:
        logger.exception("Evidence evaluation failed.")
        result["errors"].append(f"Evidence evaluation failed: {exc}")
        result.setdefault("services", [])

    for service in result.get("services", []):
        service["cve_candidates"] = []
        evidence = service.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
        if service.get("state") != "open" or not evidence.get("cve_matching_eligible"):
            continue
        try:
            service["cve_candidates"] = lookup_service_cves(service)
        except NVDLookupError as exc:
            logger.exception(
                "NVD lookup failed for %s:%s",
                service.get("host"),
                service.get("port"),
            )
            result["errors"].append(
                f"NVD lookup failed for {service.get('host')}:{service.get('port')}: {exc}"
            )

    by_service = {
        (service.get("host"), service.get("port")): service
        for service in result.get("services", [])
    }
    for finding in result.get("findings", []):
        service = by_service.get((finding.get("host"), finding.get("port")), {})
        finding["cve_candidates"] = service.get("cve_candidates", [])

    try:
        result["configuration_audit"] = audit_configurations(result)
    except (TypeError, ValueError, KeyError) as exc:
        logger.exception("Configuration audit failed.")
        result["configuration_audit"] = {"checks": [], "error": str(exc)}
        result["errors"].append(f"Configuration audit failed: {exc}")

    if include_ai:
        result["ai_analysis"] = analyze_scan(result)
    else:
        result["ai_analysis"] = {
            "status": "not_requested",
            "model": None,
            "analysis": "AI analysis was not requested.",
            "error": None,
            "label": "AI-assisted analysis",
        }
    result["risk_assessments"] = score_scan(result)
    result = explain_scan(result)
    result["recommendations"] = generate_recommendations(result)
    return attach_ai_interpretation(result)
