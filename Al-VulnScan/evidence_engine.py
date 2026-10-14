"""
AI-VulnScan - Evidence Engine

Purpose:
    Evaluate the quality of network service evidence collected by scanner.py.

Features:
    - Evaluates port state.
    - Checks service and product identification.
    - Evaluates version completeness.
    - Validates the presence and basic structure of CPE identifiers.
    - Evaluates Nmap detection confidence when available.
    - Assigns evidence quality.
    - Determines whether a service is eligible for CVE matching.
    - Generates explanations and recommended next steps.
    - Processes complete scan results.

Important:
    Strong evidence does not prove that a vulnerability exists.
    The CVE engine must independently verify affected products,
    versions, and vulnerability conditions.
"""

import re
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================

VALID_PORT_STATES = {
    "open",
    "closed",
    "filtered",
    "open|filtered",
    "unfiltered",
    "closed|filtered",
}

VALID_VERSION_STATUSES = {
    "exact",
    "range",
    "partial",
    "unknown",
}

VALID_EVIDENCE_LEVELS = {
    "strong",
    "medium",
    "weak",
    "insufficient",
}


# ============================================================
# GENERAL HELPERS
# ============================================================

def clean_string(value: Any) -> str:
    """Convert a value to a clean string safely."""

    if value is None:
        return ""

    if isinstance(value, (list, tuple, set)):
        return ", ".join(
            str(item).strip()
            for item in value
            if item is not None and str(item).strip()
        )

    return str(value).strip()


def normalize_state(state: Any) -> str:
    """Normalize a port state without inventing a state."""

    return clean_string(state).lower().replace(" ", "")


def normalize_version_status(status: Any) -> str:
    """Normalize version status and handle unknown values safely."""

    status = clean_string(status).lower()

    if status in VALID_VERSION_STATUSES:
        return status

    return "unknown"


# ============================================================
# CPE VALIDATION
# ============================================================

def normalize_cpes(cpes: Any) -> list[str]:
    """
    Normalize CPE values.

    Supports:
        - A single CPE string.
        - A list of CPE strings.
        - Empty or missing values.

    This performs basic format checking, not authoritative
    verification that a CPE describes the installed software.
    """

    if not cpes:
        return []

    if isinstance(cpes, str):
        cpes = [cpes]

    if not isinstance(cpes, (list, tuple, set)):
        return []

    results = []

    for item in cpes:
        cpe = clean_string(item)

        if not cpe:
            continue

        # Accept traditional CPE 2.2 and formatted CPE 2.3.
        if cpe.startswith("cpe:/"):
            if len(cpe.split(":")) >= 4:
                results.append(cpe)

        elif cpe.startswith("cpe:2.3:"):
            parts = cpe.split(":")

            if len(parts) >= 6:
                results.append(cpe)

    return sorted(set(results))


# ============================================================
# VERSION EVIDENCE
# ============================================================

def evaluate_version_evidence(service: dict) -> dict:
    """
    Evaluate the available version evidence.

    scanner.py supplies version_status and version_exact.
    The engine does not independently verify software versions.
    """

    version = clean_string(service.get("version"))
    version_exact = clean_string(service.get("version_exact"))

    status = normalize_version_status(
        service.get("version_status")
    )

    # If scanner.py did not provide version_status, infer a
    # conservative classification from the available text.
    if status == "unknown" and version:
        lower_version = version.lower()

        if (
            "or later" in lower_version
            or re.search(r"\b\d+(?:\.\d+)*\s*-\s*\d", version)
            or " to " in lower_version
        ):
            status = "range"

        elif any(symbol in version for symbol in ["<", ">", "+"]):
            status = "partial"

        elif re.fullmatch(r"\d+(?:\.\d+)+", version):
            status = "exact"

        else:
            status = "partial"

    # Do not treat a missing version as exact merely because
    # another field contains a value.
    if not version:
        status = "unknown"
        version_exact = ""

    # A version is eligible for exact-version matching only if
    # the scanner explicitly classified it as exact and the
    # exact version value is present.
    exact_match_eligible = (
        status == "exact"
        and bool(version_exact)
        and version_exact == version
    )

    if status == "exact" and not exact_match_eligible:
        # The scanner's exact-version metadata is inconsistent
        # or incomplete. Do not allow exact matching.
        status = "partial"

    if status == "range":
        explanation = (
            "The reported version describes a range or a "
            "version with an uncertain upper bound."
        )

    elif status == "partial":
        explanation = (
            "Version information is incomplete or cannot "
            "safely be treated as an exact version."
        )

    elif status == "exact":
        explanation = (
            "The scanner supplied an exact-format version. "
            "The installed version has not been independently verified."
        )

    else:
        explanation = "No usable version information was detected."

    return {
        "version": version,
        "version_status": status,
        "version_exact": (
            version_exact if exact_match_eligible else ""
        ),
        "exact_version_match_eligible": exact_match_eligible,
        "explanation": explanation,
    }


# ============================================================
# DETECTION CONFIDENCE
# ============================================================

def evaluate_detection_confidence(service: dict) -> dict:
    """
    Evaluate Nmap detection confidence when available.

    Nmap confidence values are commonly represented as
    percentages. Missing or malformed values remain unknown.
    """

    raw_confidence = service.get(
        "detection_confidence",
        service.get("conf", service.get("confidence"))
    )

    if raw_confidence is None or clean_string(raw_confidence) == "":
        return {
            "value": None,
            "status": "unknown",
            "explanation": (
                "Nmap detection confidence was not provided."
            ),
        }

    try:
        confidence = float(raw_confidence)
    except (TypeError, ValueError):
        return {
            "value": None,
            "status": "unknown",
            "explanation": (
                "Detection confidence was present but could "
                "not be interpreted numerically."
            ),
        }

    if not 0 <= confidence <= 100:
        return {
            "value": None,
            "status": "unknown",
            "explanation": (
                "Detection confidence was outside the expected "
                "0-100 range."
            ),
        }

    if confidence >= 90:
        status = "high"
    elif confidence >= 60:
        status = "medium"
    else:
        status = "low"

    return {
        "value": confidence,
        "status": status,
        "explanation": (
            f"Nmap reported detection confidence of {confidence:g}%."
        ),
    }


# ============================================================
# SERVICE EVIDENCE EVALUATION
# ============================================================

def evaluate_service(service: dict) -> dict:
    """
    Evaluate evidence for one discovered service.

    Returns the original service fields plus an 'evidence'
    object describing the evidence quality and limitations.
    """

    if not isinstance(service, dict):
        raise TypeError("Each service must be a dictionary.")

    # Preserve the input instead of modifying it in place.
    result = dict(service)

    port = result.get("port")
    protocol = clean_string(result.get("protocol")).lower()
    state = normalize_state(result.get("state"))

    service_name = clean_string(
        result.get("service", result.get("name"))
    )

    product = clean_string(result.get("product"))
    version_info = evaluate_version_evidence(result)
    cpes = normalize_cpes(result.get("cpe"))

    detection = evaluate_detection_confidence(result)

    reasons = []
    warnings = []
    recommendations = []

    # --------------------------------------------------------
    # Validate basic fields
    # --------------------------------------------------------

    valid_port = False

    try:
        port_number = int(port)
        valid_port = 1 <= port_number <= 65535
    except (TypeError, ValueError):
        port_number = None

    if not valid_port:
        warnings.append("Port number is missing or invalid.")

    if protocol not in {"tcp", "udp"}:
        warnings.append(
            "Protocol is missing or is not TCP/UDP."
        )

    # --------------------------------------------------------
    # Evaluate port state
    # --------------------------------------------------------

    if state == "open":
        reasons.append(
            "The scanner reports the port as open."
        )

    elif state == "open|filtered":
        warnings.append(
            "The port is open|filtered; its actual state "
            "is uncertain."
        )

    elif state == "filtered":
        warnings.append(
            "The port is filtered; the service could not "
            "be confirmed as reachable."
        )

    elif state == "closed":
        warnings.append(
            "The port is closed; this is not evidence of "
            "a currently reachable service."
        )

    elif state == "unfiltered":
        warnings.append(
            "The port is unfiltered, but that does not "
            "establish that a service is listening."
        )

    elif state == "closed|filtered":
        warnings.append(
            "The port may be closed or filtered."
        )

    else:
        warnings.append(
            "The port state is missing or unrecognized."
        )

    # --------------------------------------------------------
    # Evaluate service/product identification
    # --------------------------------------------------------

    service_identified = bool(
        service_name
        and service_name.lower() not in {
            "unknown",
            "unknown service",
        }
    )

    product_identified = bool(product)

    if service_identified:
        reasons.append(
            f"Service identified as '{service_name}'."
        )
    else:
        warnings.append(
            "No reliable service name was supplied."
        )

    if product_identified:
        reasons.append(
            f"Product reported as '{product}'."
        )
    else:
        warnings.append(
            "No product name was supplied."
        )

    # --------------------------------------------------------
    # Evaluate version evidence
    # --------------------------------------------------------

    if version_info["exact_version_match_eligible"]:
        reasons.append(
            "An exact-format version is available for "
            "candidate CVE matching."
        )

    elif version_info["version_status"] == "range":
        warnings.append(
            "Version is reported as a range; do not treat "
            "it as an exact version."
        )

    elif version_info["version_status"] == "partial":
        warnings.append(
            "Version information is partial."
        )

    else:
        warnings.append(
            "Version information is unavailable."
        )

    # --------------------------------------------------------
    # Evaluate CPE evidence
    # --------------------------------------------------------

    if cpes:
        reasons.append(
            f"{len(cpes)} syntactically valid CPE identifier(s) "
            "were supplied by the scanner."
        )
    else:
        warnings.append(
            "No usable CPE identifier was supplied."
        )

    # --------------------------------------------------------
    # Evaluate detection confidence
    # --------------------------------------------------------

    if detection["status"] == "low":
        warnings.append(
            "Nmap reported low service-detection confidence."
        )

    elif detection["status"] == "high":
        reasons.append(
            "Nmap reported high service-detection confidence."
        )

    # --------------------------------------------------------
    # Determine evidence quality
    # --------------------------------------------------------

    # An uncertain or non-open port cannot receive strong
    # service-identification evidence.
    if state != "open":
        quality = "insufficient"

        recommendations.append(
            "Confirm the port state before treating the "
            "service as reachable."
        )

    elif not service_identified:
        quality = "insufficient"

        recommendations.append(
            "Perform additional safe service-identification "
            "checks; do not guess the product from the port number."
        )

    else:
        # A simple, explainable heuristic—not a probability
        # or a validated measure of correctness.
        score = 0

        score += 2  # Open port and identified service.
        score += 1 if product_identified else 0
        score += 2 if version_info[
            "exact_version_match_eligible"
        ] else 0
        score += 1 if cpes else 0

        if detection["status"] == "high":
            score += 1
        elif detection["status"] == "low":
            score -= 1

        if score >= 5:
            quality = "strong"

        elif score >= 3:
            quality = "medium"

        else:
            quality = "weak"

        if not product_identified:
            recommendations.append(
                "Identify the software product before "
                "performing product-specific CVE matching."
            )

        if not version_info["exact_version_match_eligible"]:
            recommendations.append(
                "Obtain better version evidence before making "
                "exact-version vulnerability claims."
            )

        if not cpes:
            recommendations.append(
                "Try to obtain a reliable CPE or map the "
                "identified product to authoritative product data."
            )

    # --------------------------------------------------------
    # Determine CVE matching eligibility
    # --------------------------------------------------------

    # This only controls whether the service is suitable for
    # candidate matching. It does NOT confirm any CVE.
    cve_matching_eligible = (
        state == "open"
        and service_identified
        and product_identified
    )

    exact_version_matching_eligible = (
        cve_matching_eligible
        and version_info["exact_version_match_eligible"]
    )

    if cve_matching_eligible:
        reasons.append(
            "The service is eligible for candidate CVE lookup."
        )
    else:
        recommendations.append(
            "Do not make a product-specific CVE claim from "
            "the current service evidence."
        )

    # --------------------------------------------------------
    # Return enriched service evidence
    # --------------------------------------------------------

    result["cpe"] = cpes

    result["evidence"] = {
        "quality": quality,
        "port_state": state or "unknown",
        "service_identified": service_identified,
        "product_identified": product_identified,
        "version": version_info,
        "cpe_available": bool(cpes),
        "detection_confidence": detection,
        "cve_matching_eligible": cve_matching_eligible,
        "exact_version_matching_eligible": (
            exact_version_matching_eligible
        ),
        "reasons": reasons,
        "warnings": warnings,
        "recommendations": list(dict.fromkeys(recommendations)),
    }

    return result


# ============================================================
# COMPLETE SCAN EVALUATION
# ============================================================

def evaluate_scan(scan_result: dict) -> dict:
    """
    Evaluate all services in a scanner.py result.

    Expected input:
        {
            "target": "127.0.0.1",
            "scan_type": "standard",
            "status": "completed",
            "host_state": "up",
            "summary": {...},
            "services": [...]
        }

    Returns the scan result with enriched service evidence
    and a summary of evidence quality.
    """

    if not isinstance(scan_result, dict):
        raise TypeError("Scan result must be a dictionary.")

    result = dict(scan_result)

    services = result.get("services", [])

    if not isinstance(services, list):
        raise ValueError(
            "scan_result['services'] must be a list."
        )

    evaluated_services = [
        evaluate_service(service)
        for service in services
    ]

    quality_counts = {
        level: 0
        for level in VALID_EVIDENCE_LEVELS
    }

    eligible_count = 0
    exact_version_count = 0
    uncertain_state_count = 0

    for service in evaluated_services:
        evidence = service["evidence"]

        quality_counts[evidence["quality"]] += 1

        if evidence["cve_matching_eligible"]:
            eligible_count += 1

        if evidence["exact_version_matching_eligible"]:
            exact_version_count += 1

        if evidence["port_state"] != "open":
            uncertain_state_count += 1

    result["services"] = evaluated_services

    result["evidence_summary"] = {
        "total_services": len(evaluated_services),
        "strong": quality_counts["strong"],
        "medium": quality_counts["medium"],
        "weak": quality_counts["weak"],
        "insufficient": quality_counts["insufficient"],
        "candidate_cve_eligible_services": eligible_count,
        "exact_version_candidate_services": exact_version_count,
        "non_open_or_uncertain_state_services": (
            uncertain_state_count
        ),
        "note": (
            "Evidence quality measures the available service "
            "identification evidence. It does not confirm "
            "vulnerabilities or replace CVE verification."
        ),
    }

    return result


# ============================================================
# DISPLAY EVIDENCE SUMMARY
# ============================================================

def print_evidence_summary(scan_result: dict) -> None:
    """Print a readable evidence summary."""

    evaluated = evaluate_scan(scan_result)
    summary = evaluated["evidence_summary"]

    print("\n" + "=" * 60)
    print("AI-VulnScan - Evidence Summary")
    print("=" * 60)

    print(f"Target: {evaluated.get('target', 'Unknown')}")
    print(f"Scan type: {evaluated.get('scan_type', 'Unknown')}")
    print(f"Total services: {summary['total_services']}")

    print("\nEvidence quality:")
    print(f"  Strong:       {summary['strong']}")
    print(f"  Medium:       {summary['medium']}")
    print(f"  Weak:         {summary['weak']}")
    print(f"  Insufficient: {summary['insufficient']}")

    print("\nCVE matching readiness:")
    print(
        "  Candidate lookup eligible: "
        f"{summary['candidate_cve_eligible_services']}"
    )
    print(
        "  Exact-version candidates: "
        f"{summary['exact_version_candidate_services']}"
    )
    print(
        "  Non-open/uncertain states: "
        f"{summary['non_open_or_uncertain_state_services']}"
    )

    print("\nNote:")
    print(summary["note"])

    print("=" * 60)


# ============================================================
# OPTIONAL CLI TEST
# ============================================================

if __name__ == "__main__":

    sample_scan = {
        "target": "127.0.0.1",
        "scan_type": "standard",
        "status": "completed",
        "host_state": "up",
        "summary": {
            "total_services": 2,
            "tcp_services": 2,
            "udp_services": 0,
        },
        "services": [
            {
                "port": 6379,
                "protocol": "tcp",
                "state": "open",
                "service": "redis",
                "product": "Redis",
                "version": "7.0.15",
                "version_exact": "7.0.15",
                "version_status": "exact",
                "detection_confidence": 95,
                "cpe": [
                    "cpe:/a:redislabs:redis:7.0.15"
                ],
            },
            {
                "port": 11434,
                "protocol": "tcp",
                "state": "open|filtered",
                "service": "unknown",
                "product": "",
                "version": "",
                "version_exact": "",
                "version_status": "unknown",
                "detection_confidence": None,
                "cpe": [],
            },
        ],
    }

    evaluated = evaluate_scan(sample_scan)

    print_evidence_summary(evaluated)

    print("\nIndividual service results:")

    for service in evaluated["services"]:
        print(
            f"\n{service.get('port')}/"
            f"{service.get('protocol')}"
        )
        print(f"  Service: {service.get('service', 'unknown')}")
        print(f"  Evidence: {service['evidence']['quality']}")
        print(
            "  Candidate CVE lookup eligible: "
            f"{service['evidence']['cve_matching_eligible']}"
        )

        for warning in service["evidence"]["warnings"]:
            print(f"  Warning: {warning}")