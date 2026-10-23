"""Non-destructive configuration checks over collected evidence."""

from __future__ import annotations

from typing import Any

_HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "id": "CFG-HTTP-001",
        "description": "HSTS was not observed on an HTTPS response.",
        "guidance": "Consider a suitable Strict-Transport-Security policy after confirming all relevant subdomains support HTTPS.",
    },
    "Content-Security-Policy": {
        "id": "CFG-HTTP-002",
        "description": "Content-Security-Policy was not observed.",
        "guidance": "Review whether a Content-Security-Policy is appropriate for this application.",
    },
    "X-Content-Type-Options": {
        "id": "CFG-HTTP-003",
        "description": "X-Content-Type-Options was not observed.",
        "guidance": "Consider setting X-Content-Type-Options: nosniff where compatible.",
    },
}


def audit_configurations(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Audit only HTTP response headers explicitly present in scan evidence."""
    checks: list[dict[str, Any]] = []
    for service in scan_result.get("services", []):
        fingerprint = service.get("fingerprint", {})
        probe = fingerprint.get("http_probe") or {}
        if not probe.get("success"):
            continue
        headers = probe.get("security_headers", {})
        https = probe.get("scheme") == "https"
        for header, definition in _HEADER_CHECKS.items():
            if header == "Strict-Transport-Security" and not https:
                continue
            present = bool(headers.get(header))
            checks.append(
                {
                    "check_id": definition["id"],
                    "host": service.get("host", ""),
                    "port": service.get("port"),
                    "status": "observed" if present else "not_observed",
                    "name": header,
                    "evidence": {
                        "source": "authorized_http_get",
                        "scheme": probe.get("scheme"),
                        "http_status": probe.get("http_status"),
                        "value": headers.get(header),
                    },
                    "interpretation": (
                        f"{header} was observed."
                        if present
                        else definition["description"]
                    ),
                    "guidance": definition["guidance"],
                    "confidence": "medium" if present else "low",
                    "limitation": (
                        "A single unauthenticated response does not establish the policy for every route or client."
                    ),
                }
            )
    return {
        "checks": checks,
        "summary": {
            "completed": len(checks),
            "not_run": (
                "HTTP checks require an explicitly enabled, authorized HTTP probe; "
                "TLS certificate configuration is not currently assessed."
            ),
        },
    }
