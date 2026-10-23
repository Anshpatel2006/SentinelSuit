"""Interactive CLI for authorized AI-VulnScan assessments."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import REPORT_OUTPUT_DIR
from pipeline import analyze_scan_result
from report_generator import generate_reports
from scan_comparator import compare_scans, format_comparison_report
from scan_storage import ScanStorage
from scanner import SCAN_PROFILES, scan_target, target_host_count, validate_ports, validate_target

try:
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    Console = None
    Panel = None

logger = logging.getLogger(__name__)
console = Console() if Console else None
DEFAULT_TARGET = "127.0.0.1"


def _print(message: str, *, style: str | None = None) -> None:
    if console:
        console.print(message, style=style)
    else:
        print(message)


def print_banner() -> None:
    """Display a simple banner without making Rich mandatory."""
    title = "AI-VulnScan — Authorized Network Inventory"
    if console and Panel:
        console.print(Panel(title, subtitle="Nmap · NVD · local Ollama"))
    else:
        print(f"\n{title}\nNmap | NVD | local Ollama\n")


def _ask(prompt: str, default: str = "") -> str:
    if console:
        suffix = f" [{default}]" if default else ""
        value = console.input(f"{prompt}{suffix}: ")
    else:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ")
    return value.strip() or default


def _confirm(prompt: str, required_text: str = "YES") -> bool:
    return _ask(f"{prompt} Type {required_text} to continue").strip() == required_text


def print_scan_summary(result: dict[str, Any]) -> None:
    """Display observed states and candidates without asserting vulnerability."""
    services = result.get("services", [])
    _print(f"\nScan status: {result.get('status', 'unknown')}")
    _print(f"Hosts: {len(result.get('hosts', []))}; port records: {len(services)}")
    for service in services:
        _print(
            f"  {service.get('host')}:{service.get('port')}/{service.get('protocol')} "
            f"{service.get('state')} {service.get('service', '')} "
            f"{service.get('product', '')} {service.get('version', '')}"
        )
    candidates = [
        cve
        for service in services
        for cve in service.get("cve_candidates", [])
    ]
    _print(f"NVD CVE candidates: {len(candidates)}")
    for cve in candidates[:20]:
        _print(f"  {cve.get('id')} [{cve.get('match_status', 'candidate')}]")
    for assessment in result.get("risk_assessments", []):
        risk = assessment.get("risk", {})
        _print(
            f"Risk: {assessment.get('name')} — "
            f"{risk.get('score', 0)}/100 ({risk.get('category', 'Informational')})"
        )
    ai = result.get("ai_analysis", {})
    _print(f"AI analysis: {ai.get('status', 'not run')}")


def run_comparison(storage: ScanStorage) -> None:
    """Compare two explicitly selected saved scans and write a report."""
    history = storage.list_scans()
    if len(history) < 2:
        _print("At least two saved scans are required for comparison.")
        return
    for index, item in enumerate(history, start=1):
        _print(
            f"{index}. {item.get('scan_id')} | {item.get('target')} | "
            f"{item.get('created_at')} | {item.get('status')}"
        )
    try:
        first = int(_ask("Older scan number"))
        second = int(_ask("Newer scan number"))
        if first == second or not (1 <= first <= len(history) and 1 <= second <= len(history)):
            raise ValueError("Choose two different scan numbers from the list.")
        older = storage.load_scan(history[first - 1]["scan_id"])
        newer = storage.load_scan(history[second - 1]["scan_id"])
        comparison = compare_scans(older, newer)
        report = format_comparison_report(comparison)
        directory = REPORT_OUTPUT_DIR / "comparisons"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = directory / f"comparison-{stamp}.md"
        with path.open("x", encoding="utf-8") as handle:
            handle.write(report)
        _print(f"Comparison report: {path}")
    except (ValueError, IndexError, KeyError, OSError) as exc:
        logger.exception("Could not compare saved scans.")
        _print(f"Comparison failed: {exc}")


def run_scan() -> None:
    """Collect target/profile scope, confirm authorization, and run pipeline."""
    target_input = _ask("Target IP, hostname, or strict CIDR", DEFAULT_TARGET)
    try:
        target = validate_target(target_input)
        hosts_count = target_host_count(target)
    except ValueError as exc:
        _print(f"Invalid target: {exc}")
        return

    _print("Available scan profiles:")
    profile_keys = (
        "quick",
        "standard",
        "deep",
        "aggressive",
        "all_tcp_udp",
        "udp",
        "comprehensive",
    )
    for index, key in enumerate(profile_keys, start=1):
        profile = SCAN_PROFILES[key]
        _print(f"  {index}. {profile['name']} — {profile['description']}")
    profile_choice = _ask(f"Select profile (1-{len(profile_keys)})", "2")
    if not profile_choice.isdigit() or not 1 <= int(profile_choice) <= len(profile_keys):
        _print("Invalid scan profile selection.")
        return
    profile = profile_keys[int(profile_choice) - 1]

    try:
        tcp_text = _ask("Custom TCP ports (comma-separated; blank uses profile defaults)")
        udp_text = _ask("Custom UDP ports (comma-separated; blank uses profile defaults)")
        tcp_ports = validate_ports(tcp_text or None)
        udp_ports = validate_ports(udp_text or None)
    except ValueError as exc:
        _print(f"Invalid ports: {exc}")
        return

    if profile in {"aggressive", "all_tcp_udp"} and (
        tcp_ports is not None or udp_ports is not None
    ):
        _print(
            f"The {SCAN_PROFILES[profile]['name']} profile scans all of its ports "
            "and cannot be combined with custom ports. Choose another profile "
            "for a custom-port scan."
        )
        return

    _print(
        f"\nScope to scan: {target}\n"
        f"Address count: {hosts_count}\n"
        f"Profile: {SCAN_PROFILES[profile]['name']}\n"
        f"Custom TCP ports: {tcp_ports or 'none'}\n"
        f"Custom UDP ports: {udp_ports or 'none'}\n"
        "When custom ports are supplied, only those selected protocol/port sets are scanned.\n"
        "UDP open|filtered states will not be treated as confirmed open."
    )
    if not _confirm("Confirm you are authorized to assess this exact scope"):
        _print("Scan cancelled; no network traffic was sent.")
        return
    if hosts_count > 1 and not _confirm(
        f"Confirm scanning all {hosts_count} addresses in this CIDR",
        f"SCAN {hosts_count} HOSTS",
    ):
        _print("Multi-host scan cancelled; no network traffic was sent.")
        return
    if profile == "comprehensive" and not _confirm(
        "This broader scan can take longer. Confirm explicitly",
        "COMPREHENSIVE",
    ):
        _print("Comprehensive scan cancelled; no network traffic was sent.")
        return
    if profile == "aggressive" and not _confirm(
        "This scans all TCP ports with stronger version probes and may take much longer. "
        "NSE scripts are not enabled. Confirm explicitly",
        "AGGRESSIVE",
    ):
        _print("Aggressive scan cancelled; no network traffic was sent.")
        return
    if profile == "all_tcp_udp" and not _confirm(
        "This probes every TCP and UDP port with stronger version detection. "
        "It may take a very long time; UDP open|filtered is not confirmed open. "
        "NSE scripts are not enabled. Confirm explicitly",
        "ALL TCP+UDP",
    ):
        _print("All TCP and UDP scan cancelled; no network traffic was sent.")
        return
    enable_http = _confirm(
        "Enable one low-impact HTTP GET for confirmed HTTP services? This may create normal server-side activity",
        "HTTP",
    )

    _print("Starting Nmap scan. Do not run the application as root by default.")
    try:
        scanned = scan_target(
            target,
            scan_type=profile,
            custom_tcp_ports=tcp_ports,
            custom_udp_ports=udp_ports,
            authorized=True,
            confirm_multiple_hosts=hosts_count > 1,
            confirm_aggressive=profile == "aggressive",
            confirm_all_ports=profile == "all_tcp_udp",
        )
    except (ValueError, PermissionError) as exc:
        _print(f"Scan was not started: {exc}")
        return
    except KeyboardInterrupt:
        _print("Scan interrupted.")
        return
    except Exception as exc:
        logger.exception("Unexpected scan failure.")
        _print(f"Scan failed: {exc}")
        return

    _print("Processing Nmap evidence, rules, and CVE candidates...")
    result = analyze_scan_result(
        scanned,
        enable_http_probe=enable_http,
        include_ai=True,
    )
    print_scan_summary(result)

    storage = ScanStorage()
    xml_text = result.pop("nmap_xml", None)
    try:
        saved = storage.save_scan(result, nmap_xml=xml_text)
        result["scan_id"] = saved["scan_id"]
        paths = generate_reports(result, scan_id=saved["scan_id"])
        storage.update_scan(
            saved["scan_id"],
            {
                "report_locations": paths,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        )
    except (OSError, ValueError, TypeError) as exc:
        logger.exception("Scan storage or report generation failed.")
        _print(f"Could not persist the complete scan/report set: {exc}")
        return

    _print(f"Scan ID: {saved['scan_id']}")
    for format_name, path in paths.items():
        _print(f"{format_name.upper()} report: {Path(path)}")
    if result.get("errors"):
        _print(f"Partial results contain {len(result['errors'])} recorded error(s).")


def main() -> None:
    """Run a new authorized scan or compare saved scan history."""
    print_banner()
    storage = ScanStorage()
    action = _ask("Choose: 1) new scan  2) compare scan history", "1")
    if action == "2":
        run_comparison(storage)
    elif action == "1":
        run_scan()
    else:
        _print("Choose 1 or 2.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _print("Application stopped by user.")
