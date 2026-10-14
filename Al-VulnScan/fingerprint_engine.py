"""
AI-VulnScan - Fingerprint Engine

Purpose:
    Improve service identification using additional, low-impact
    checks when Nmap's service fingerprint is incomplete.

Features:
    - Preserves original Nmap evidence.
    - Identifies services with incomplete product/version details.
    - Optionally inspects HTTP response headers and page content.
    - Records product candidates and supporting observations.
    - Assigns a conservative fingerprint confidence.
    - Never invents an exact software version.
    - Does not perform exploitation or vulnerability testing.

Requirements:
    Python standard library only.

Important:
    Run only against systems you own or are authorized to assess.
"""

import re
import socket
import ssl

from urllib.error import HTTPError, URLError
from urllib.request import (
    Request,
    HTTPSHandler,
    HTTPHandler,
    build_opener,
)


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_TIMEOUT = 3

MAX_RESPONSE_BYTES = 16_384

HTTP_SERVICES = {
    "http",
    "https",
    "http-alt",
    "http-proxy",
    "https-alt",
    "ipp",
}

UNKNOWN_NAMES = {
    "",
    "unknown",
    "unknown service",
    "tcpwrapped",
}


# ============================================================
# GENERAL HELPERS
# ============================================================

def clean_string(value):
    """Convert a value to a stripped string safely."""

    if value is None:
        return ""

    return str(value).strip()


def is_unknown(value):
    """Check whether a service/product name is unknown."""

    return clean_string(value).lower() in UNKNOWN_NAMES


def valid_port(port):
    """Validate a TCP port number."""

    try:
        port = int(port)
    except (TypeError, ValueError):
        return False

    return 1 <= port <= 65535


def get_service_name(service):
    """Support both scanner.py naming conventions."""

    return clean_string(
        service.get("service", service.get("name", ""))
    )


def get_product_name(service):
    """Return the original detected product name."""

    return clean_string(service.get("product", ""))


def get_version(service):
    """Return the original detected version."""

    return clean_string(service.get("version", ""))


# ============================================================
# INITIAL FINGERPRINT ASSESSMENT
# ============================================================

def assess_initial_fingerprint(service):
    """
    Assess how much identification information Nmap supplied.

    This is a completeness assessment, not proof that the
    detected software identification is correct.
    """

    service_name = get_service_name(service)
    product = get_product_name(service)
    version = get_version(service)

    cpe = service.get("cpe", [])

    if isinstance(cpe, str):
        cpe = [cpe]

    if not isinstance(cpe, (list, tuple, set)):
        cpe = []

    cpe = [
        clean_string(item)
        for item in cpe
        if clean_string(item)
    ]

    missing = []

    if is_unknown(service_name):
        missing.append("service_name")

    if not product:
        missing.append("product")

    if not version:
        missing.append("version")

    if not cpe:
        missing.append("cpe")

    if not missing:
        status = "identified"
    elif service_name and not is_unknown(service_name):
        status = "partially_identified"
    else:
        status = "unidentified"

    return {
        "status": status,
        "original_service": service_name,
        "original_product": product,
        "original_version": version,
        "original_cpe": cpe,
        "missing_fields": missing,
    }


# ============================================================
# HTTP IDENTIFICATION
# ============================================================

def inspect_http_service(
    target,
    port,
    use_https=False,
    timeout=DEFAULT_TIMEOUT,
):
    """
    Inspect a service with one HTTP GET request to '/'.

    This function:
        - Does not submit credentials.
        - Does not send application-specific commands.
        - Does not follow redirects.
        - Limits the amount of response data read.
        - Records response headers and a short body sample.

    The request may still cause normal server-side logging
    or application activity.
    """

    scheme = "https" if use_https else "http"

    url = f"{scheme}://{target}:{port}/"

    request = Request(
        url,
        headers={
            "User-Agent": "AI-VulnScan-Fingerprint/1.0",
            "Accept": "text/html,application/json,*/*",
            "Connection": "close",
        },
        method="GET",
    )

    # Do not follow redirects automatically. A redirect could
    # otherwise send the probe to a different host.
    opener = build_opener(
        HTTPHandler(),
        HTTPSHandler(context=ssl.create_default_context()),
        NoRedirectHandler(),
    )

    try:
        with opener.open(request, timeout=timeout) as response:
            status_code = response.status
            headers = response.headers
            body = response.read(MAX_RESPONSE_BYTES)

    except HTTPError as error:
        # HTTP 4xx/5xx responses are still useful evidence that
        # an HTTP-speaking endpoint responded.
        status_code = error.code
        headers = error.headers

        try:
            body = error.read(MAX_RESPONSE_BYTES)
        except Exception:
            body = b""

    except (URLError, socket.timeout, TimeoutError, OSError) as error:
        return {
            "success": False,
            "scheme": scheme,
            "port": port,
            "url": url,
            "error": str(error),
            "observations": [],
            "product_candidates": [],
        }

    except Exception as error:
        return {
            "success": False,
            "scheme": scheme,
            "port": port,
            "url": url,
            "error": str(error),
            "observations": [],
            "product_candidates": [],
        }

    server_header = clean_string(
        headers.get("Server", "")
    )

    powered_by = clean_string(
        headers.get("X-Powered-By", "")
    )

    content_type = clean_string(
        headers.get("Content-Type", "")
    )

    body_text = body.decode(
        "utf-8",
        errors="replace",
    )

    observations = []

    candidates = []

    observations.append(
        f"HTTP response received with status {status_code}."
    )

    if server_header:
        observations.append(
            f"Server header: {server_header}"
        )

        candidates.append({
            "product": server_header,
            "source": "http_server_header",
            "confidence": "low",
            "reason": (
                "The HTTP Server header identifies a claimed "
                "server product, but headers can be customized."
            ),
        })

    if powered_by:
        observations.append(
            f"X-Powered-By header: {powered_by}"
        )

        candidates.append({
            "product": powered_by,
            "source": "http_x_powered_by_header",
            "confidence": "low",
            "reason": (
                "The X-Powered-By header provides a software "
                "candidate but can be absent or spoofed."
            ),
        })

    if content_type:
        observations.append(
            f"Content-Type: {content_type}"
        )

    # A product-specific marker is accepted only as a candidate.
    # It is never treated as independent proof of a product.
    lower_body = body_text.lower()

    if "ollama is running" in lower_body:
        candidates.append({
            "product": "Ollama",
            "source": "http_response_body_marker",
            "confidence": "medium",
            "reason": (
                "The response contains a recognizable Ollama "
                "message. Verify the product independently."
            ),
        })

    # Extract the HTML title, if one exists.
    title_match = re.search(
        r"<title[^>]*>(.*?)</title>",
        body_text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if title_match:
        title = re.sub(
            r"\s+",
            " ",
            title_match.group(1),
        ).strip()

        if title:
            observations.append(
                f"HTML title: {title[:200]}"
            )

    # Remove duplicate candidates while preserving order.
    unique_candidates = []
    seen = set()

    for candidate in candidates:
        key = (
            candidate["product"].lower(),
            candidate["source"],
        )

        if key not in seen:
            seen.add(key)
            unique_candidates.append(candidate)

    return {
        "success": True,
        "scheme": scheme,
        "port": port,
        "url": url,
        "http_status": status_code,
        "server_header": server_header,
        "powered_by": powered_by,
        "content_type": content_type,
        "body_sample": body_text[:1000],
        "observations": observations,
        "product_candidates": unique_candidates,
    }


# ============================================================
# REDIRECT HANDLING
# ============================================================

from urllib.request import HTTPRedirectHandler


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent HTTP probes from automatically following redirects."""

    def redirect_request(
        self,
        request,
        response,
        code,
        message,
        headers,
        new_url,
    ):
        return None


# ============================================================
# SERVICE FINGERPRINTING
# ============================================================

def fingerprint_service(
    target,
    service,
    enable_http_probe=False,
    timeout=DEFAULT_TIMEOUT,
):
    """
    Fingerprint one service using existing Nmap evidence
    and optionally one low-impact HTTP request.

    Original Nmap product/version values are never overwritten.

    Args:
        target:
            Target IP address or hostname from the scan.

        service:
            One service dictionary returned by scanner.py.

        enable_http_probe:
            If True, probe HTTP services and optionally unknown
            services with a simple HTTP GET request.

        timeout:
            Per-request timeout in seconds.

    Returns:
        A new dictionary containing original service data and
        a separate 'fingerprint' result.
    """

    if not isinstance(service, dict):
        raise TypeError("service must be a dictionary")

    result = dict(service)

    port = service.get("port")

    state = clean_string(
        service.get("state", "")
    ).lower()

    protocol = clean_string(
        service.get("protocol", "")
    ).lower()

    initial = assess_initial_fingerprint(service)

    observations = [
        "Fingerprint assessment started.",
    ]

    candidates = []

    probe_result = None

    # Never send an application probe to a port that is not
    # explicitly reported as open TCP.
    if state != "open":
        observations.append(
            "Additional probing skipped because the port "
            "is not confirmed open."
        )

    elif protocol != "tcp":
        observations.append(
            "HTTP fingerprinting is only enabled for TCP."
        )

    elif not enable_http_probe:
        observations.append(
            "Active HTTP probing is disabled."
        )

    elif not valid_port(port):
        observations.append(
            "Active probing skipped because the port is invalid."
        )

    else:
        service_name = get_service_name(service).lower()

        # Probe recognized HTTP services automatically when the
        # user enables probing. Unknown services can be checked
        # with HTTP only when explicitly enabled by the caller.
        should_probe = (
            service_name in HTTP_SERVICES
            or is_unknown(service_name)
        )

        if should_probe:
            # Prefer HTTPS only if Nmap explicitly reported
            # a TLS tunnel or an HTTPS service.
            tunnel = clean_string(
                service.get("tunnel", "")
            ).lower()

            use_https = (
                tunnel == "ssl"
                or service_name in {"https", "https-alt"}
            )

            probe_result = inspect_http_service(
                target=target,
                port=int(port),
                use_https=use_https,
                timeout=timeout,
            )

            if probe_result["success"]:
                observations.extend(
                    probe_result["observations"]
                )

                candidates.extend(
                    probe_result["product_candidates"]
                )
            else:
                observations.append(
                    "HTTP identification did not succeed: "
                    + probe_result.get("error", "Unknown error")
                )

        else:
            observations.append(
                "HTTP probe skipped because Nmap did not "
                "identify this as an HTTP service and the "
                "service name was not unknown."
            )

    # Determine whether additional evidence improved the
    # identification. This is not a validated probability.
    original_product = get_product_name(service)
    original_version = get_version(service)

    if original_product and original_version:
        status = "existing_identification"
    elif candidates:
        status = "candidate_found"
    elif probe_result and probe_result.get("success"):
        status = "endpoint_responded"
    else:
        status = "insufficient_evidence"

    recommendations = []

    if not original_product:
        recommendations.append(
            "Product identification remains unverified. "
            "Do not infer the product from the port number."
        )

    if not original_version:
        recommendations.append(
            "No verified exact version was established. "
            "Do not invent a version or claim exact-version matches."
        )

    if candidates:
        recommendations.append(
            "Verify product candidates against additional "
            "independent evidence before using them for CVE matching."
        )

    result["fingerprint"] = {
        "status": status,
        "initial_assessment": initial,
        "observations": observations,
        "product_candidates": candidates,
        "http_probe": probe_result,
        "version_verified": False,
        "recommendations": recommendations,
        "limitations": [
            "HTTP headers can be spoofed or customized.",
            "A response body marker is not conclusive proof "
            "of product identity.",
            "No exact software version is inferred by this module.",
            "Fingerprinting does not establish that a CVE applies.",
        ],
    }

    return result


# ============================================================
# COMPLETE SCAN FINGERPRINTING
# ============================================================

def fingerprint_scan(
    scan_result,
    enable_http_probe=False,
    timeout=DEFAULT_TIMEOUT,
):
    """
    Fingerprint every service in a scanner.py result.

    The original scan structure is preserved.
    Each service receives an additional 'fingerprint' object.
    """

    if not isinstance(scan_result, dict):
        raise TypeError("scan_result must be a dictionary")

    result = dict(scan_result)

    target = clean_string(
        scan_result.get("target", "")
    )

    if not target:
        raise ValueError(
            "scan_result must contain a target"
        )

    services = scan_result.get("services", [])

    if not isinstance(services, list):
        raise ValueError(
            "scan_result['services'] must be a list"
        )

    results = []

    for service in services:
        results.append(
            fingerprint_service(
                target=target,
                service=service,
                enable_http_probe=enable_http_probe,
                timeout=timeout,
            )
        )

    result["services"] = results

    candidate_count = sum(
        1
        for service in results
        if service["fingerprint"]["product_candidates"]
    )

    probed_count = sum(
        1
        for service in results
        if service["fingerprint"]["http_probe"] is not None
    )

    result["fingerprint_summary"] = {
        "total_services": len(results),
        "services_with_product_candidates": candidate_count,
        "services_where_http_probe_was_attempted": probed_count,
        "active_http_probing_enabled": enable_http_probe,
        "note": (
            "Candidates require verification. This engine "
            "does not verify exact versions or confirm CVEs."
        ),
    }

    return result


# ============================================================
# DISPLAY RESULTS
# ============================================================

def print_fingerprint_summary(scan_result):
    """Print a readable fingerprint summary."""

    summary = scan_result.get(
        "fingerprint_summary",
        {},
    )

    print("\n" + "=" * 60)
    print("AI-VulnScan - Fingerprint Summary")
    print("=" * 60)

    print(
        f"Target: {scan_result.get('target', 'Unknown')}"
    )

    print(
        f"Total services: "
        f"{summary.get('total_services', 0)}"
    )

    print(
        "Services with product candidates: "
        f"{summary.get('services_with_product_candidates', 0)}"
    )

    print(
        "Services where HTTP probing was attempted: "
        f"{summary.get('services_where_http_probe_was_attempted', 0)}"
    )

    print("\nIndividual results:")

    for service in scan_result.get("services", []):
        port = service.get("port", "?")
        protocol = service.get("protocol", "?")

        fingerprint = service.get("fingerprint", {})

        print(
            f"\n{port}/{protocol}: "
            f"{fingerprint.get('status', 'unknown')}"
        )

        for candidate in fingerprint.get(
            "product_candidates",
            [],
        ):
            print(
                f"  Candidate: {candidate['product']}"
            )
            print(
                f"  Source: {candidate['source']}"
            )
            print(
                f"  Confidence: {candidate['confidence']}"
            )

        for recommendation in fingerprint.get(
            "recommendations",
            [],
        ):
            print(f"  Recommendation: {recommendation}")

    print("=" * 60)


# ============================================================
# BASIC TEST
# ============================================================

if __name__ == "__main__":

    sample_scan = {
        "target": "127.0.0.1",
        "scan_type": "standard",
        "status": "completed",
        "services": [
            {
                "port": 11434,
                "protocol": "tcp",
                "state": "open",
                "service": "unknown",
                "product": "",
                "version": "",
                "version_exact": "",
                "version_status": "unknown",
                "cpe": [],
            },
            {
                "port": 6379,
                "protocol": "tcp",
                "state": "open",
                "service": "redis",
                "product": "Redis",
                "version": "7.0.15",
                "version_exact": "7.0.15",
                "version_status": "exact",
                "cpe": [
                    "cpe:/a:redislabs:redis:7.0.15"
                ],
            },
        ],
    }

    # The default test performs NO network requests.
    result = fingerprint_scan(
        sample_scan,
        enable_http_probe=False,
    )

    print_fingerprint_summary(result)