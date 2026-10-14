"""NVD CVE lookup using configuration from .env."""

import requests

from config import (
    NVD_API_KEY,
    NVD_API_URL,
    NVD_TIMEOUT,
    NVD_RESULTS_LIMIT,
)


def search_cves(service_name, version=""):
    """
    Search the official NVD API for CVE candidates.

    Returns a list of CVE IDs for compatibility with main.py.
    These results are candidates, not confirmed vulnerabilities.
    """
    service_name = str(service_name or "").strip()
    version = str(version or "").strip()

    if not service_name:
        return []

    keyword = f"{service_name} {version}".strip()

    headers = {
        "Accept": "application/json",
        "User-Agent": "AI-VulnScan/1.0",
    }

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max(int(NVD_RESULTS_LIMIT), 1), 100),
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=NVD_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()

    except requests.RequestException as exc:
        print(f"[ERROR] NVD lookup failed: {exc}")
        return []

    except (ValueError, TypeError):
        print("[ERROR] Invalid NVD response or configuration.")
        return []

    cve_ids = []

    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        if cve_id:
            cve_ids.append(cve_id)

    return cve_ids


def search_cve_details(service_name, version=""):
    """
    Return detailed candidate CVE records for reporting or AI analysis.
    """
    service_name = str(service_name or "").strip()
    version = str(version or "").strip()

    if not service_name:
        return []

    keyword = f"{service_name} {version}".strip()

    headers = {
        "Accept": "application/json",
        "User-Agent": "AI-VulnScan/1.0",
    }

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max(int(NVD_RESULTS_LIMIT), 1), 100),
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=NVD_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()

    except requests.RequestException as exc:
        print(f"[ERROR] NVD lookup failed: {exc}")
        return []

    except (ValueError, TypeError):
        print("[ERROR] Invalid NVD response or configuration.")
        return []

    records = []

    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})

        descriptions = cve.get("descriptions", [])
        description = next(
            (
                entry.get("value", "")
                for entry in descriptions
                if entry.get("lang") == "en"
            ),
            "",
        )

        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "Unknown"

        for metric_name in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            entries = metrics.get(metric_name, [])

            if entries:
                metric = entries[0]
                cvss_data = metric.get("cvssData", {})

                cvss_score = cvss_data.get("baseScore")
                severity = (
                    cvss_data.get("baseSeverity")
                    or metric.get("baseSeverity")
                    or "Unknown"
                )
                break

        cve_id = cve.get("id", "")

        records.append({
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published": cve.get("published", ""),
            "source": "NIST National Vulnerability Database",
            "match_status": "candidate",
        })

    return records