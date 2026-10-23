"""Normalize Nmap XML into stable host and service records."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any
from xml.etree import ElementTree


class NmapXMLParseError(ValueError):
    """Raised when Nmap XML is malformed or has an invalid root."""


def _timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse a complete or partial Nmap XML document.

    Port states are preserved exactly as observed. Only ``open`` is
    considered confirmed open; filtered and open|filtered remain uncertain.
    """
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise NmapXMLParseError("Nmap XML is empty.")
    if len(xml_text.encode("utf-8")) > 20 * 1024 * 1024:
        raise NmapXMLParseError("Nmap XML exceeds the 20 MiB safety limit.")
    if re.search(r"<!\s*ENTITY\b|<!DOCTYPE[^>]*\[", xml_text, flags=re.IGNORECASE):
        raise NmapXMLParseError("XML entity declarations and internal DTD subsets are not accepted.")

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise NmapXMLParseError(f"Malformed Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapXMLParseError("XML root element is not <nmaprun>.")

    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        addresses = [
            {
                "address": node.get("addr", ""),
                "type": node.get("addrtype", ""),
                "vendor": node.get("vendor", ""),
            }
            for node in host_node.findall("address")
            if node.get("addr")
        ]
        hostnames = [
            node.get("name", "")
            for node in host_node.findall("./hostnames/hostname")
            if node.get("name")
        ]
        host_address = next(
            (item["address"] for item in addresses if item["type"] in {"ipv4", "ipv6"}),
            addresses[0]["address"] if addresses else "",
        )
        host_services: list[dict[str, Any]] = []
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            version = service_node.get("version", "") if service_node is not None else ""
            version_status, version_exact = _version_evidence(version)
            raw_confidence = (
                _int_or_none(service_node.get("conf"))
                if service_node is not None
                else None
            )
            service: dict[str, Any] = {
                "host": host_address,
                "hostnames": hostnames,
                "port": _int_or_none(port_node.get("portid")),
                "protocol": port_node.get("protocol", "").lower(),
                "state": state,
                "reason": state_node.get("reason", "") if state_node is not None else "",
                "service": service_node.get("name", "") if service_node is not None else "",
                "product": service_node.get("product", "") if service_node is not None else "",
                "version": version,
                "version_status": version_status,
                "version_exact": version_exact,
                "extrainfo": service_node.get("extrainfo", "") if service_node is not None else "",
                "tunnel": service_node.get("tunnel", "") if service_node is not None else "",
                "method": service_node.get("method", "") if service_node is not None else "",
                "detection_confidence": raw_confidence,
                "detection_confidence_scale": (
                    "nmap_1_to_10"
                    if raw_confidence is not None and 1 <= raw_confidence <= 10
                    else "unknown"
                ),
                "cpe": [
                    cpe.text.strip()
                    for cpe in (service_node.findall("cpe") if service_node is not None else [])
                    if cpe.text and cpe.text.strip()
                ],
                "scripts": [
                    {"id": script.get("id", ""), "output": script.get("output", "")}
                    for script in port_node.findall("script")
                ],
            }
            host_services.append(service)
            services.append(service)

        os_matches = [
            {
                "name": match.get("name", ""),
                "accuracy": _int_or_none(match.get("accuracy")),
                "classes": [
                    dict(os_class.attrib)
                    for os_class in match.findall("osclass")
                ],
            }
            for match in host_node.findall("./os/osmatch")
        ]
        hosts.append(
            {
                "address": host_address,
                "addresses": addresses,
                "hostnames": hostnames,
                "state": status_node.get("state", "unknown") if status_node is not None else "unknown",
                "state_reason": status_node.get("reason", "") if status_node is not None else "",
                "start_time": _timestamp(host_node.get("starttime")),
                "end_time": _timestamp(host_node.get("endtime")),
                "os": os_matches,
                "services": host_services,
            }
        )

    finished = root.find("./runstats/finished")
    run_errors = [
        item.text.strip()
        for item in root.findall("./runstats/hosts")
        if item.text and item.text.strip()
    ]
    if finished is not None and finished.get("errormsg"):
        run_errors.append(finished.get("errormsg", ""))
    exit_status = finished.get("exit", "") if finished is not None else ""
    status = "completed" if exit_status == "success" else "partial"
    if finished is None and not hosts:
        status = "failed"

    return {
        "nmap_version": root.get("version", ""),
        "scanner": root.get("scanner", ""),
        "scan_started": _timestamp(root.get("start")),
        "scan_finished": _timestamp(finished.get("time")) if finished is not None else None,
        "status": status,
        "completion": exit_status or "unknown",
        "hosts": hosts,
        "services": services,
        "errors": run_errors,
    }


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _version_evidence(value: str) -> tuple[str, str]:
    version = value.strip()
    if not version:
        return "unknown", ""
    if re.fullmatch(r"\d+(?:\.\d+)+", version):
        return "exact", version
    return "partial", ""
