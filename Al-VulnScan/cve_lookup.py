"""NVD CVE 2.0 candidate lookup and conservative CPE applicability checks."""

from __future__ import annotations

import logging
import time
from functools import lru_cache
from typing import Any

import requests
from packaging.version import InvalidVersion, Version

from config import (
    NVD_API_KEY,
    NVD_API_URL,
    NVD_RESULTS_LIMIT,
    NVD_RETRIES,
    NVD_TIMEOUT,
)

logger = logging.getLogger(__name__)
_SESSION = requests.Session()


class NVDLookupError(RuntimeError):
    """Raised when NVD cannot return a usable response."""


def _split_cpe(cpe: str) -> list[str]:
    fields: list[str] = []
    field: list[str] = []
    escaped = False
    for character in cpe:
        if escaped:
            field.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(field))
            field.clear()
        else:
            field.append(character)
    if escaped:
        field.append("\\")
    fields.append("".join(field))
    return fields


def _cpe_parts(cpe: str) -> tuple[str, str, str] | None:
    fields = _split_cpe(cpe)
    if len(fields) < 6 or fields[0:2] != ["cpe", "2.3"]:
        return None
    return fields[3].lower(), fields[4].lower(), fields[5].lower()


def _compare_versions(left: str, right: str) -> int | None:
    try:
        a, b = Version(left), Version(right)
    except InvalidVersion:
        return None
    return (a > b) - (a < b)


def _within_range(version: str, match: dict[str, Any]) -> bool | None:
    criteria = match.get("criteria", "")
    parts = _cpe_parts(criteria)
    affected_version = parts[2] if parts else ""
    boundaries = (
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    )
    if affected_version in {"", "*"} and not any(match.get(key) for key in boundaries):
        return None
    if affected_version == "-":
        return False
    if affected_version not in {"", "*"}:
        comparison = _compare_versions(version, affected_version)
        if comparison is None:
            return None
        if comparison != 0:
            return False

    checks = (
        ("versionStartIncluding", lambda result: result >= 0),
        ("versionStartExcluding", lambda result: result > 0),
        ("versionEndIncluding", lambda result: result <= 0),
        ("versionEndExcluding", lambda result: result < 0),
    )
    for key, accepts in checks:
        boundary = match.get(key)
        if boundary:
            comparison = _compare_versions(version, str(boundary))
            if comparison is None:
                return None
            if not accepts(comparison):
                return False
    return True


def _cpe_matches(record: dict[str, Any], service_cpes: list[str], version: str) -> tuple[str, str | None]:
    service_identities = {
        (parts[0], parts[1])
        for cpe in service_cpes
        if (parts := _cpe_parts(cpe)) is not None
    }
    if not service_identities:
        return "candidate", None

    candidates: list[dict[str, Any]] = []

    def collect_matches(node: dict[str, Any]) -> None:
        matches = node.get("cpeMatch", [])
        if isinstance(matches, list):
            candidates.extend(item for item in matches if isinstance(item, dict))
        children = node.get("children", [])
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    collect_matches(child)

    configurations = record.get("configurations", [])
    if not isinstance(configurations, list):
        configurations = []
    for configuration in configurations:
        nodes = configuration.get("nodes", []) if isinstance(configuration, dict) else []
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    collect_matches(node)

    identity_matches = [
        item
        for item in candidates
        if item.get("vulnerable", True)
        and (parts := _cpe_parts(str(item.get("criteria", ""))))
        and (parts[0], parts[1]) in service_identities
    ]
    if not identity_matches:
        return "candidate", None
    if not version:
        return "product_match", "Exact version evidence is unavailable."

    results = [_within_range(version, match) for match in identity_matches]
    if any(result is True for result in results):
        return "version_match", "A NVD vulnerable CPE entry matches the observed CPE and version range."
    if results and all(result is False for result in results):
        return "version_mismatch", "The observed exact version is outside the listed affected CPE ranges."
    return "insufficient_evidence", "NVD CPE version constraints could not be compared reliably."


def _request_nvd(params: dict[str, str | int]) -> dict[str, Any]:
    headers = {"Accept": "application/json", "User-Agent": "AI-VulnScan/2.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    last_error: Exception | None = None
    for attempt in range(NVD_RETRIES + 1):
        try:
            response = _SESSION.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=NVD_TIMEOUT,
            )
            if response.status_code in {403, 429} or response.status_code >= 500:
                if attempt < NVD_RETRIES:
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        delay = min(max(float(retry_after), 0.0), 5.0)
                    except ValueError:
                        delay = min(0.5 * (2**attempt), 4.0)
                    time.sleep(delay)
                    continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("NVD response was not a JSON object.")
            return payload
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
            if attempt < NVD_RETRIES and (
                not isinstance(exc, requests.HTTPError)
                or exc.response is None
                or exc.response.status_code >= 500
            ):
                time.sleep(min(0.5 * (2**attempt), 4.0))
                continue
            break
    logger.warning("NVD lookup failed: %s", last_error)
    raise NVDLookupError("NVD lookup failed after bounded retries.") from last_error


@lru_cache(maxsize=256)
def _search(query: str, cpe_name: str) -> tuple[dict[str, Any], ...]:
    params: dict[str, str | int] = {
        "resultsPerPage": min(max(NVD_RESULTS_LIMIT, 1), 100),
    }
    if cpe_name:
        params["cpeName"] = cpe_name
    elif query:
        params["keywordSearch"] = query
    else:
        return ()
    payload = _request_nvd(params)
    items = payload.get("vulnerabilities", [])
    if not isinstance(items, list):
        logger.warning("NVD returned an unexpected vulnerabilities structure.")
        return ()
    return tuple(item for item in items if isinstance(item, dict))


def lookup_service_cves(service: dict[str, Any]) -> list[dict[str, Any]]:
    """Return NVD candidate records with conservative CPE/version statuses."""
    if not isinstance(service, dict):
        raise TypeError("service must be a dictionary.")
    if service.get("state") != "open":
        return []
    product = str(service.get("product") or "").strip()
    service_name = str(service.get("service") or "").strip()
    exact_version = str(service.get("version_exact") or "").strip()
    if not exact_version and service.get("version_status") == "exact":
        exact_version = str(service.get("version") or "").strip()
    if not product:
        logger.info("Skipping NVD lookup: product evidence is unavailable.")
        return []

    service_cpes = service.get("cpe", [])
    if isinstance(service_cpes, str):
        service_cpes = [service_cpes]
    if not isinstance(service_cpes, (list, tuple, set)):
        service_cpes = []
    service_cpes = [str(item).strip() for item in service_cpes if item]
    exact_cpe = next(
        (item for item in service_cpes if _cpe_parts(item) and "*" not in item),
        "",
    )
    query = " ".join(part for part in (product, exact_version) if part)
    raw_items = _search(query if not exact_cpe else "", exact_cpe)
    if not raw_items and exact_cpe:
        raw_items = _search(query, "")

    records: list[dict[str, Any]] = []
    for item in raw_items:
        cve = item.get("cve", {})
        if not isinstance(cve, dict) or not cve.get("id"):
            continue
        descriptions = cve.get("descriptions", [])
        if not isinstance(descriptions, list):
            descriptions = []
        description = next(
            (
                entry.get("value", "")
                for entry in descriptions
                if isinstance(entry, dict) and entry.get("lang") == "en"
            ),
            "",
        )
        score = None
        severity = "Unknown"
        for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            cve_metrics = cve.get("metrics", {})
            if not isinstance(cve_metrics, dict):
                cve_metrics = {}
            metrics = cve_metrics.get(metric_name, [])
            if not isinstance(metrics, list):
                metrics = []
            if metrics and isinstance(metrics[0], dict):
                cvss_data = metrics[0].get("cvssData", {})
                if not isinstance(cvss_data, dict):
                    cvss_data = {}
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or metrics[0].get("baseSeverity") or "Unknown"
                break

        status, explanation = _cpe_matches(cve, service_cpes, exact_version)
        applicability_confidence = {
            "version_match": "medium",
            "product_match": "low",
            "version_mismatch": "medium",
            "insufficient_evidence": "unknown",
            "candidate": "low",
        }.get(status, "unknown")
        cve_references = cve.get("references", [])
        if not isinstance(cve_references, list):
            cve_references = []
        references = [
            ref.get("url", "")
            for ref in cve_references
            if isinstance(ref, dict) and ref.get("url")
        ]
        records.append(
            {
                "id": cve["id"],
                "description": description,
                "cvss_score": score,
                "severity": severity,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "references": references,
                "source": "NIST National Vulnerability Database",
                "match_status": status,
                "applicability_confidence": applicability_confidence,
                "applicability_note": explanation,
                "applicability_verified": False,
                "evidence": {
                    "product": product,
                    "service": service_name,
                    "version": exact_version or None,
                    "cpe": service_cpes,
                },
            }
        )
    return records


def search_cve_details(service_name: str, version: str = "") -> list[dict[str, Any]]:
    """Compatibility wrapper; keyword results remain candidates."""
    service = {
        "state": "open",
        "service": service_name,
        "product": service_name,
        "version": version,
        "version_status": "exact" if version else "unknown",
        "version_exact": version,
        "cpe": [],
    }
    return lookup_service_cves(service)


def search_cves(service_name: str, version: str = "") -> list[str]:
    """Return candidate CVE identifiers for legacy callers."""
    return [record["id"] for record in search_cve_details(service_name, version)]
