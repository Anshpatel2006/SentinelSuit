"""Bounded Nmap scanning with explicit authorization and XML output."""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Iterable

from config import MAX_CIDR_SIZE, MAX_CUSTOM_PORTS, MAX_HOST_COUNT, SCAN_TIMEOUT
from nmap_xml_parser import NmapXMLParseError, parse_nmap_xml

logger = logging.getLogger(__name__)

SCAN_PROFILES: dict[str, dict[str, str]] = {
    "quick": {
        "name": "Quick Discovery",
        "description": "Top 100 TCP ports with light version detection.",
    },
    "standard": {
        "name": "Standard Vulnerability Scan",
        "description": "Top 1,000 TCP ports with light version detection.",
    },
    "deep": {
        "name": "Deep Scan",
        "description": "All TCP ports; this may take substantially longer.",
    },
    "aggressive": {
        "name": "Aggressive (All TCP Ports)",
        "description": (
            "All TCP ports with stronger service-version probes; longer and noisier. "
            "Requires explicit confirmation. NSE scripts are not enabled."
        ),
    },
    "all_tcp_udp": {
        "name": "All TCP + UDP Ports",
        "description": (
            "All TCP and UDP ports with stronger service-version probes; may take "
            "a very long time and UDP results can remain open|filtered. "
            "Requires separate explicit confirmation."
        ),
    },
    "udp": {
        "name": "UDP Scan",
        "description": "Top 50 UDP ports; open|filtered is not confirmed open.",
    },
    "comprehensive": {
        "name": "Comprehensive Scan",
        "description": "Explicitly requested broader TCP inventory.",
    },
    "full": {
        "name": "Comprehensive Scan",
        "description": "Explicitly requested broader TCP inventory.",
    },
}

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def target_host_count(target: str) -> int:
    """Return the exact number of addresses in a validated scope."""
    value = target.strip()
    try:
        return ipaddress.ip_network(value, strict=True).num_addresses
    except ValueError:
        try:
            ipaddress.ip_address(value)
            return 1
        except ValueError:
            return 1


def validate_target(target: str) -> str:
    """Validate an IP, strict CIDR network, or DNS hostname without resolving it."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target cannot be empty.")
    target = target.strip()
    if any(char.isspace() for char in target) or target.startswith("-"):
        raise ValueError("Target contains invalid whitespace or option syntax.")

    try:
        address = ipaddress.ip_address(target)
        return str(address)
    except ValueError:
        pass

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=True)
        except ValueError as exc:
            raise ValueError("CIDR must be a valid network with its network address.") from exc
        if network.num_addresses > MAX_CIDR_SIZE:
            raise ValueError(
                f"CIDR contains {network.num_addresses} addresses; "
                f"the configured limit is {MAX_CIDR_SIZE}."
            )
        if network.num_addresses > MAX_HOST_COUNT:
            raise ValueError(
                f"CIDR exceeds the configured host limit ({MAX_HOST_COUNT})."
            )
        return str(network)

    if re.fullmatch(r"[0-9.]+", target):
        raise ValueError("Malformed numeric IP address.")

    hostname = target.rstrip(".")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Hostname is not valid IDNA.") from exc
    if not ascii_hostname or len(ascii_hostname) > 253:
        raise ValueError("Hostname length is invalid.")
    labels = ascii_hostname.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Target must be an IP, strict CIDR, or valid DNS hostname.")
    if len(labels) > 1 and all(label.isdigit() for label in labels):
        raise ValueError("Malformed numeric IP address.")
    return ascii_hostname


def validate_ports(ports: Iterable[int | str] | str | None) -> list[int] | None:
    """Validate a list or comma-separated string of TCP/UDP port numbers."""
    if ports is None or ports == "":
        return None
    if isinstance(ports, str):
        values: Iterable[int | str] = ports.split(",")
    else:
        values = ports
    parsed: set[int] = set()
    for item in values:
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid port: {item!r}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Port {port} must be between 1 and 65535.")
        parsed.add(port)
    if not parsed:
        return None
    if len(parsed) > MAX_CUSTOM_PORTS:
        raise ValueError(f"At most {MAX_CUSTOM_PORTS} custom ports are allowed.")
    return sorted(parsed)


def build_scan_arguments(
    scan_type: str = "standard",
    custom_tcp_ports: Iterable[int | str] | str | None = None,
    custom_udp_ports: Iterable[int | str] | str | None = None,
) -> list[str]:
    """Build Nmap argv without shell parsing or shell command strings."""
    if scan_type not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan profile: {scan_type}")
    tcp_ports = validate_ports(custom_tcp_ports)
    udp_ports = validate_ports(custom_udp_ports)
    if scan_type == "aggressive" and (tcp_ports is not None or udp_ports is not None):
        raise ValueError(
            "The aggressive profile scans all TCP ports and cannot be combined with custom ports."
        )
    if scan_type == "all_tcp_udp" and (tcp_ports is not None or udp_ports is not None):
        raise ValueError(
            "The all TCP and UDP profile scans all ports and cannot be combined with custom ports."
        )

    timing = "-T2" if scan_type == "udp" else "-T3"
    if tcp_ports is not None or udp_ports is not None:
        args = [timing, "-sV", "--version-light"]
        selections: list[str] = []
        if tcp_ports is not None:
            args.append("-sT")
            selections.append(f"T:{','.join(map(str, tcp_ports))}")
        if udp_ports is not None:
            args.append("-sU")
            selections.append(f"U:{','.join(map(str, udp_ports))}")
        args.extend(["-p", ",".join(selections)])
    elif scan_type == "quick":
        args = ["-sT", "-T3", "--top-ports", "100", "-sV", "--version-light"]
    elif scan_type == "standard":
        args = ["-sT", "-T3", "--top-ports", "1000", "-sV", "--version-light"]
    elif scan_type == "deep":
        args = ["-sT", "-T3", "-p-", "-sV", "--version-light"]
    elif scan_type == "aggressive":
        args = ["-sT", "-T3", "-p-", "-sV", "--version-intensity", "7"]
    elif scan_type == "all_tcp_udp":
        args = [
            "-sT",
            "-sU",
            "-T2",
            "-p",
            "T:1-65535,U:1-65535",
            "-sV",
            "--version-intensity",
            "7",
        ]
    elif scan_type == "udp":
        args = ["-sU", "-T2", "--top-ports", "50", "-sV", "--version-light"]
    else:
        args = ["-sT", "-T3", "--top-ports", "2000", "-sV", "--version-light"]

    args.extend(["--reason"])
    return args


def _failure(target: str, profile: str, message: str, *, status: str = "failed") -> dict[str, Any]:
    logger.error("Nmap scan %s for %s: %s", status, target, message)
    now = datetime.now(timezone.utc).isoformat()
    return {
        "target": target,
        "scope": target,
        "authorization_attested": True,
        "scan_type": profile,
        "status": status,
        "scan_started": now,
        "scan_finished": now,
        "nmap_version": None,
        "nmap_exit_code": None,
        "nmap_stderr": "",
        "scan_arguments": [],
        "hosts": [],
        "services": [],
        "errors": [message],
        "summary": {"total_services": 0, "tcp_services": 0, "udp_services": 0},
        "nmap_xml": None,
    }


def scan_target(
    target_ip: str,
    scan_type: str = "standard",
    custom_tcp_ports: Iterable[int | str] | str | None = None,
    custom_udp_ports: Iterable[int | str] | str | None = None,
    *,
    authorized: bool = False,
    confirm_multiple_hosts: bool = False,
    confirm_aggressive: bool = False,
    confirm_all_ports: bool = False,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Scan an explicitly authorized scope and return one stable result mapping."""
    target = validate_target(target_ip)
    if not authorized:
        raise PermissionError(
            "Scanning requires explicit confirmation that the target is authorized."
        )
    count = target_host_count(target)
    if count > 1 and not confirm_multiple_hosts:
        raise PermissionError(
            f"Scope contains {count} addresses; explicit multi-host confirmation is required."
        )
    if count > MAX_HOST_COUNT:
        raise ValueError(f"Scope exceeds the configured host limit ({MAX_HOST_COUNT}).")
    if scan_type == "aggressive" and not confirm_aggressive:
        raise PermissionError(
            "The aggressive all-TCP-ports profile requires explicit confirmation."
        )
    if scan_type == "all_tcp_udp" and not confirm_all_ports:
        raise PermissionError(
            "The all TCP and UDP ports profile requires explicit confirmation."
        )
    arguments = build_scan_arguments(scan_type, custom_tcp_ports, custom_udp_ports)
    time_limit = timeout if timeout is not None else SCAN_TIMEOUT
    if not isinstance(time_limit, int) or not 1 <= time_limit <= 3600:
        raise ValueError("Scan timeout must be between 1 and 3600 seconds.")

    binary = shutil.which("nmap")
    if binary is None:
        return _failure(target, scan_type, "Nmap was not found on PATH; install Nmap first.")

    command = [binary, target, *arguments, "--host-timeout", f"{time_limit}s", "-oX", "-"]
    started = datetime.now(timezone.utc).isoformat()
    logger.info("Starting authorized %s scan for scope %s", scan_type, target)
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=time_limit,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        partial_xml = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
        if partial_xml:
            try:
                parsed = parse_nmap_xml(partial_xml)
            except NmapXMLParseError:
                parsed = None
            if parsed:
                parsed.update(
                    target=target,
                    scope=target,
                    scan_type=scan_type,
                    status="partial",
                    scan_started=started,
                    scan_finished=datetime.now(timezone.utc).isoformat(),
                    errors=[f"Scan exceeded the {time_limit}-second timeout."],
                    nmap_xml=partial_xml,
                    nmap_exit_code=None,
                    nmap_stderr=(stderr or "")[:5000],
                    scan_arguments=arguments,
                    authorization_attested=True,
                    multiple_hosts_confirmed=count > 1 and confirm_multiple_hosts,
                )
                return _add_summary(parsed)
        return _failure(target, scan_type, f"Scan exceeded the {time_limit}-second timeout.", status="partial")
    except OSError as exc:
        return _failure(target, scan_type, f"Could not execute Nmap: {exc}")

    xml_text = process.stdout or ""
    try:
        result = parse_nmap_xml(xml_text)
    except NmapXMLParseError as exc:
        detail = process.stderr.strip()
        message = str(exc)
        if detail:
            message = f"{message} Nmap stderr: {detail[:1000]}"
        failed = _failure(target, scan_type, message, status="failed")
        failed.update(scan_started=started, nmap_xml=xml_text or None)
        return failed

    result.update(
        target=target,
        scope=target,
        scan_type=scan_type,
        scan_started=result.get("scan_started") or started,
        scan_finished=result.get("scan_finished") or datetime.now(timezone.utc).isoformat(),
        nmap_xml=xml_text,
        nmap_exit_code=process.returncode,
        nmap_stderr=(process.stderr or "")[:5000],
        scan_arguments=arguments,
        authorization_attested=True,
        multiple_hosts_confirmed=count > 1 and confirm_multiple_hosts,
        errors=list(result.get("errors", [])),
    )
    if process.returncode:
        stderr = process.stderr.strip()
        detail = stderr[:1000] if stderr else f"Nmap exited with status {process.returncode}."
        result["errors"].append(detail)
        result["status"] = "partial" if result["hosts"] else "failed"
    result = _add_summary(result)
    logger.info(
        "Nmap scan ended with status %s; %d hosts and %d port records",
        result["status"],
        len(result["hosts"]),
        len(result["services"]),
    )
    return result


def _add_summary(result: dict[str, Any]) -> dict[str, Any]:
    services = result.get("services", [])
    result["summary"] = {
        "total_services": len(services),
        "confirmed_open": sum(service.get("state") == "open" for service in services),
        "filtered_or_uncertain": sum(
            service.get("state") in {"filtered", "open|filtered", "closed|filtered"}
            for service in services
        ),
        "tcp_services": sum(service.get("protocol") == "tcp" for service in services),
        "udp_services": sum(service.get("protocol") == "udp" for service in services),
    }
    return result


def display_scan_table(services: list[dict[str, Any]]) -> None:
    """Print a compact service summary without requiring Rich."""
    for service in services:
        print(
            f"{service.get('host', ''):>39} "
            f"{service.get('port', '?')}/{service.get('protocol', '?'):<4} "
            f"{service.get('state', 'unknown'):<14} "
            f"{service.get('service', '')} {service.get('product', '')} "
            f"{service.get('version', '')}".strip()
        )


def show_scan_profiles() -> None:
    """Display available scan profiles."""
    for key, profile in SCAN_PROFILES.items():
        if key == "full":
            continue
        print(f"{key}: {profile['name']} — {profile['description']}")
