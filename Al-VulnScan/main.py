"""
AI-VulnScan
-----------
AI-powered network vulnerability scanner using:
- Nmap for network scanning
- NVD for CVE candidate lookup
- Ollama for AI-assisted analysis
- Markdown for reporting
"""

from pathlib import Path

import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from scanner import scan_target
from cve_lookup import search_cves
from ai_analyzer import analyze_with_llm
from report_generator import append_report_md


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

console = Console()

REPORT_FILE = Path(__file__).resolve().parent / "report.md"


# --------------------------------------------------
# BANNER
# --------------------------------------------------

def print_banner():
    """Display the application banner."""

    ascii_banner = pyfiglet.figlet_format("AI-VulnScan")
    console.print(f"[bold blue]{ascii_banner}[/bold blue]")

    banner_text = Text()
    banner_text.append(
        "AI-Powered Network Vulnerability Scanner\n",
        style="bold magenta",
    )
    banner_text.append(
        "Nmap + NVD CVE Lookup + Local AI (Ollama)\n"
    )
    banner_text.append(
        "Created by Rajkumar Kumawat\n"
    )

    console.print(
        Panel(
            banner_text,
            expand=False,
            border_style="green",
        )
    )


# --------------------------------------------------
# REPORT INITIALIZATION
# --------------------------------------------------

def initialize_report(target_ip):
    """Create a new Markdown report."""

    try:
        with REPORT_FILE.open(
            "w",
            encoding="utf-8",
        ) as report:

            report.write(
                "# AI-VulnScan Network Vulnerability Report\n\n"
            )
            report.write(
                f"**Target:** `{target_ip}`\n\n"
            )
            report.write(
                "**Important:** CVE keyword-search results are "
                "candidates and do not independently confirm "
                "that a vulnerability affects the target.\n\n"
            )
            report.write("---\n\n")

    except OSError as exc:
        console.print(
            f"[bold red]Could not initialize report: {exc}[/bold red]"
        )
        return False

    return True


# --------------------------------------------------
# TARGET INPUT
# --------------------------------------------------

def get_target():
    """Read and validate the target input."""

    target = console.input(
        "[bold yellow]Enter target IP address: [/bold yellow]"
    ).strip()

    if not target:
        console.print(
            "[bold red]Target IP address cannot be empty.[/bold red]"
        )
        return None

    return target


# --------------------------------------------------
# CUSTOM PORT INPUT
# --------------------------------------------------

def get_custom_ports():
    """
    Read optional TCP ports.

    Returns:
        None: use the selected scan profile's default ports.
        list[int]: scan the specified TCP ports.
    """

    choice = console.input(
        "[bold cyan]Specify custom TCP ports? (y/n): [/bold cyan]"
    ).strip().lower()

    if choice not in ("y", "yes"):
        return None

    ports_input = console.input(
        "[bold cyan]Enter TCP ports separated by commas "
        "(example: 22,80,443): [/bold cyan]"
    ).strip()

    if not ports_input:
        console.print(
            "[yellow]No custom ports entered. "
            "Using the selected scan profile.[/yellow]"
        )
        return None

    try:
        ports = sorted(
            {
                int(item.strip())
                for item in ports_input.split(",")
            }
        )

    except ValueError:
        console.print(
            "[bold red]Invalid port input. "
            "Use comma-separated numbers.[/bold red]"
        )
        return None

    if any(port < 1 or port > 65535 for port in ports):
        console.print(
            "[bold red]Ports must be between 1 and 65535.[/bold red]"
        )
        return None

    return ports


# --------------------------------------------------
# SCAN RESULT NORMALIZATION
# --------------------------------------------------

def extract_services(scan_result):
    """
    Extract service dictionaries from scan_target().

    Supports:
        1. A structured dictionary containing a 'services' list.
        2. A direct list of service dictionaries.

    Returns:
        list[dict] or None if the structure is invalid.
    """

    if scan_result is None:
        console.print(
            "[bold red]The scanner returned no results.[/bold red]"
        )
        return None

    if isinstance(scan_result, dict):
        services = scan_result.get("services")

        if services is None:
            console.print(
                "[bold red]The scan result does not contain "
                "a 'services' field.[/bold red]"
            )
            console.print(
                f"[yellow]Available fields: "
                f"{list(scan_result.keys())}[/yellow]"
            )
            return None

    elif isinstance(scan_result, list):
        services = scan_result

    else:
        console.print(
            "[bold red]Unexpected scan result type: "
            f"{type(scan_result).__name__}[/bold red]"
        )
        return None

    if not isinstance(services, list):
        console.print(
            "[bold red]The scanner's services field is not a list.[/bold red]"
        )
        return None

    valid_services = []

    for item in services:
        if not isinstance(item, dict):
            console.print(
                "[yellow]Skipping unexpected service entry: "
                f"{item!r}[/yellow]"
            )
            continue

        valid_services.append(item)

    return valid_services


# --------------------------------------------------
# CVE LOOKUP
# --------------------------------------------------

def lookup_cves(product, version):
    """
    Retrieve potential CVE matches.

    Keyword-search results must not be treated as confirmed
    vulnerabilities without affected-version verification.
    """

    if not product or product.strip().lower() in (
        "unknown",
        "unknown service",
    ):
        console.print(
            "[yellow]Skipping CVE lookup because "
            "product information is unavailable.[/yellow]"
        )
        return []

    try:
        cves = search_cves(
            product.strip(),
            (version or "").strip(),
        )

        if cves is None:
            return []

        # The expected API returns a list of CVE IDs.
        if isinstance(cves, list):
            return cves

        console.print(
            "[yellow]Unexpected CVE lookup result type: "
            f"{type(cves).__name__}[/yellow]"
        )
        return []

    except Exception as exc:
        console.print(
            f"[bold red]CVE lookup failed: {exc}[/bold red]"
        )
        return []


# --------------------------------------------------
# AI ANALYSIS
# --------------------------------------------------

def run_ai_analysis(port, product, version, cves):
    """Run local AI analysis for one discovered service."""

    service_name = f"{product} {version}".strip()

    try:
        return analyze_with_llm(
            port,
            service_name,
            cves,
        )

    except Exception as exc:
        console.print(
            f"[bold red]AI analysis failed: {exc}[/bold red]"
        )

        return (
            "AI analysis could not be completed. "
            "Review the Nmap evidence and CVE candidates manually."
        )


# --------------------------------------------------
# PROCESS ONE SERVICE
# --------------------------------------------------

def process_service(service):
    """Perform CVE lookup, AI analysis, and report generation."""

    port = service.get("port", "Unknown")
    protocol = service.get("protocol", "tcp")
    state = service.get("state", "unknown")

    product = (
        service.get("product")
        or service.get("service")
        or "Unknown"
    )

    version = service.get("version") or ""

    console.print(
        f"\n[bold cyan]Port {port}/{protocol}[/bold cyan]"
    )
    console.print(f"State: {state}")
    console.print(f"Product: {product}")
    console.print(
        f"Version: {version if version else 'Not identified'}"
    )

    # Do not perform vulnerability matching on ports that
    # Nmap has not confirmed as open.
    if state != "open":
        console.print(
            "[yellow]Skipping CVE lookup because this port "
            "is not confirmed open.[/yellow]"
        )
        cves = []

    else:
        console.print(
            "[cyan]Searching NVD for potential CVE candidates...[/cyan]"
        )
        cves = lookup_cves(product, version)

    if cves:
        console.print(
            "[yellow]Potential CVE candidates: "
            f"{', '.join(str(cve) for cve in cves)}[/yellow]"
        )
    else:
        console.print(
            "[dim]No CVE candidates returned.[/dim]"
        )

    console.print(
        "[cyan]Sending service information to local AI...[/cyan]"
    )

    ai_text = run_ai_analysis(
        port,
        product,
        version,
        cves,
    )

    console.print(
        "[bold magenta]AI Analysis:[/bold magenta]"
    )
    console.print(str(ai_text))

    try:
        append_report_md(
            service,
            cves,
            ai_text,
        )

        console.print(
            f"[green]Report updated for port {port}.[/green]"
        )

    except Exception as exc:
        console.print(
            f"[bold red]Could not append service report: {exc}[/bold red]"
        )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():
    """Run the AI-VulnScan application."""

    print_banner()

    target_ip = get_target()

    if not target_ip:
        return

    custom_ports = get_custom_ports()

    if not initialize_report(target_ip):
        return

    console.print(
        f"\n[bold yellow]Starting scan of "
        f"{target_ip}...[/bold yellow]\n"
    )

    try:
        scan_result = scan_target(
            target_ip=target_ip,
            scan_type="standard",
            custom_tcp_ports=custom_ports,
        )

    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]Scan interrupted by user.[/bold yellow]"
        )
        return

    except Exception as exc:
        console.print(
            f"[bold red]Scanner failed: {exc}[/bold red]"
        )
        return

    if scan_result is None:
        console.print(
            "[bold red]Scan failed. Check the Nmap output "
            "and scan permissions.[/bold red]"
        )
        return

    services = extract_services(scan_result)

    if services is None:
        console.print(
            "[bold red]Could not process the scanner's result. "
            "Check scanner.py's return structure.[/bold red]"
        )
        return

    console.print(
        f"\n[bold green]Scan finished. "
        f"Processing {len(services)} services...[/bold green]"
    )

    if not services:
        console.print(
            "[yellow]No services were returned by the scanner.[/yellow]"
        )
        return

    for service in services:
        try:
            process_service(service)

        except KeyboardInterrupt:
            console.print(
                "\n[bold yellow]Processing interrupted by user.[/bold yellow]"
            )
            break

        except Exception as exc:
            console.print(
                f"[bold red]Error processing service: {exc}[/bold red]"
            )
            continue

    console.print(
        "\n[bold green]Scan processing finished.[/bold green]"
    )
    console.print(
        f"[bold cyan]Report location: {REPORT_FILE}[/bold cyan]"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]Application stopped by user.[/bold yellow]"
        )