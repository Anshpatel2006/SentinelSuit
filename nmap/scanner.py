import ipaddress
import socket
import nmap

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt

console = Console()


# ============================================================
# SCAN PROFILES
# ============================================================

SCAN_PROFILES = {
    "1": {
        "name": "Quick Discovery",
        "description": "Fast identification of exposed services.",
        "when_to_use": (
            "Use for initial reconnaissance, quick checks, "
            "or scanning many hosts quickly."
        ),
        "scan_type": "quick",
    },
    "2": {
        "name": "Standard Vulnerability Scan",
        "description": (
            "All TCP ports + service/version detection + CPE "
            "+ safe security checks."
        ),
        "when_to_use": (
            "Use for normal vulnerability assessment and CVE analysis. "
            "This is the recommended/default scan."
        ),
        "scan_type": "standard",
    },
    "3": {
        "name": "Deep Vulnerability Scan",
        "description": (
            "TCP + UDP + service/version detection + OS detection "
            "+ safe security checks."
        ),
        "when_to_use": (
            "Use when you need deeper assessment and suspect "
            "important UDP services or additional OS information."
        ),
        "scan_type": "deep",
    },
    "4": {
        "name": "UDP Assessment",
        "description": "Dedicated UDP service discovery.",
        "when_to_use": (
            "Use when you specifically need to identify UDP attack "
            "surfaces such as DNS, SNMP, NTP, DHCP, etc."
        ),
        "scan_type": "udp",
    },
    "5": {
        "name": "Comprehensive Security Assessment",
        "description": (
            "Broad TCP + UDP + OS + service/version detection "
            "+ safe checks."
        ),
        "when_to_use": (
            "Use for a full security assessment when scan time "
            "is less important than maximum discovery coverage."
        ),
        "scan_type": "full",
    },
}


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target):
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    # IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Hostname
    try:
        socket.gethostbyname(target)
        return target
    except socket.gaierror:
        raise ValueError(f"Invalid target: {target}")


# ============================================================
# PORT VALIDATION
# ============================================================

def validate_ports(ports):
    if not ports:
        return None

    validated = []

    for port in ports:
        try:
            port = int(port)
        except ValueError:
            raise ValueError(f"Invalid port: {port}")

        if not 1 <= port <= 65535:
            raise ValueError(
                f"Port {port} is invalid. "
                "Port must be between 1 and 65535."
            )

        validated.append(port)

    return sorted(set(validated))


# ============================================================
# SCAN ARGUMENT BUILDER
# ============================================================

def build_scan_arguments(
    scan_type="standard",
    custom_tcp_ports=None,
    custom_udp_ports=None,
):
    """
    Build Nmap arguments for each AI-VulnScan scan profile.

    Profiles:
        quick   -> Fast TCP discovery
        standard -> Full TCP + service/version + safe NSE
        deep    -> Full TCP + common UDP + OS + safe NSE
        udp     -> Common UDP assessment
        full    -> Full TCP + common UDP + OS + safe NSE
    """

    # --------------------------------------------------------
    # TCP PORT CONFIGURATION
    # --------------------------------------------------------

    if custom_tcp_ports:
        tcp_ports = ",".join(
            map(str, custom_tcp_ports)
        )
    else:
        # IMPORTANT:
        # Do NOT expand this to 1,2,3,...65535.
        # Nmap understands the range directly.
        tcp_ports = "1-65535"

    # --------------------------------------------------------
    # UDP PORT CONFIGURATION
    # --------------------------------------------------------

    if custom_udp_ports:

        udp_ports = ",".join(
            map(str, custom_udp_ports)
        )

    else:

        # Common UDP services.
        udp_ports = (
            "53,"       # DNS
            "67-68,"    # DHCP
            "69,"       # TFTP
            "123,"      # NTP
            "135,"      # MS RPC
            "137-138,"  # NetBIOS
            "161-162,"  # SNMP
            "500,"      # ISAKMP
            "514,"      # Syslog
            "520,"      # RIP
            "1900,"     # SSDP
            "4500"      # IPsec NAT-T
        )

    # --------------------------------------------------------
    # PROFILE 1 - QUICK DISCOVERY
    # --------------------------------------------------------

    if scan_type == "quick":

        return (
            "-Pn "
            "-T4 "
            "-sS "
            "--top-ports 100 "
            "-sV"
        )

    # --------------------------------------------------------
    # PROFILE 2 - STANDARD VULNERABILITY SCAN
    # --------------------------------------------------------

    elif scan_type == "standard":

        return (
            "-Pn "
            "-T4 "
            "-sS "
            f"-p T:{tcp_ports} "
            "-sV "
            "--script=safe"
        )

    # --------------------------------------------------------
    # PROFILE 3 - DEEP VULNERABILITY SCAN
    # --------------------------------------------------------

    elif scan_type == "deep":

        return (
            "-Pn "
            "-T4 "
            "-sS "
            "-sU "
            f"-p T:{tcp_ports},U:{udp_ports} "
            "-sV "
            "-O "
            "--script=safe"
        )

    # --------------------------------------------------------
    # PROFILE 4 - UDP ASSESSMENT
    # --------------------------------------------------------

    elif scan_type == "udp":

        return (
            "-Pn "
            "-T4 "
            "-sU "
            f"-p U:{udp_ports} "
            "-sV"
        )

    # --------------------------------------------------------
    # PROFILE 5 - COMPREHENSIVE SECURITY ASSESSMENT
    # --------------------------------------------------------

    elif scan_type == "full":

        return (
            "-Pn "
            "-T4 "
            "-sS "
            "-sU "
            f"-p T:{tcp_ports},U:{udp_ports} "
            "-sV "
            "-O "
            "--script=safe"
        )

    else:

        raise ValueError(
            f"Unknown scan type: {scan_type}"
        )

# ============================================================
# CPE EXTRACTION
# ============================================================

def extract_cpes(service):
    cpes = service.get("cpe", [])

    if isinstance(cpes, str):
        cpes = [cpes]

    if not cpes:
        return []

    return [
        cpe.strip()
        for cpe in cpes
        if cpe and cpe.strip()
    ]


# ============================================================
# VERSION ANALYSIS
# ============================================================

def determine_version_status(version):
    if not version:
        return "unknown"

    version = version.strip()

    if " or later" in version.lower():
        return "range"

    if any(symbol in version for symbol in ["-", " to "]):
        return "range"

    if any(symbol in version for symbol in ["+", "<", ">", "="]):
        return "partial"

    parts = version.split(".")

    # Example: 7.0.15
    if all(part.isdigit() for part in parts):
        return "exact"

    # Example: 2.4
    if len(parts) >= 2 and all(
        part.isdigit() for part in parts
    ):
        return "partial"

    return "partial"


# ============================================================
# SERVICE PARSER
# ============================================================

def parse_service(port, protocol, service):
    version = service.get("version", "") or ""

    return {
        "port": int(port),
        "protocol": protocol,

        "state": service.get("state", ""),
        "reason": service.get("reason", ""),

        "service": service.get("name", "") or "",

        "product": service.get("product", "") or "",

        "version": version,

        "version_exact": (
            version
            if determine_version_status(version) == "exact"
            else ""
        ),

        "version_status": determine_version_status(version),

        "extrainfo": service.get("extrainfo", "") or "",

        "tunnel": service.get("tunnel", "") or "",

        "method": service.get("method", "") or "",

        "detection_confidence": service.get(
            "conf",
            service.get("confidence", "")
        ),

        "cpe": extract_cpes(service),
    }


# ============================================================
# OS INFORMATION
# ============================================================

def parse_os(host):
    os_matches = host.get("osmatch", [])

    results = []

    for match in os_matches:
        results.append({
            "name": match.get("name", ""),
            "accuracy": match.get("accuracy", ""),
            "line": match.get("line", ""),
        })

    return results


# ============================================================
# SCAN FUNCTION
# ============================================================

def scan_target(
    target_ip,
    scan_type="standard",
    custom_tcp_ports=None,
    custom_udp_ports=None,
):
    """
    Main scanner.

    Returns structured scan results that can later be passed
    to the CVE engine and AI analyzer.
    """

    try:
        target_ip = validate_target(target_ip)

        custom_tcp_ports = validate_ports(custom_tcp_ports)
        custom_udp_ports = validate_ports(custom_udp_ports)

    except ValueError as e:
        console.print(
            f"[red]Validation error:[/red] {e}"
        )
        return None

    arguments = build_scan_arguments(
        scan_type=scan_type,
        custom_tcp_ports=custom_tcp_ports,
        custom_udp_ports=custom_udp_ports,
    )

    console.print()

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {target_ip}\n"
            f"[bold cyan]Scan Profile:[/bold cyan] "
            f"{SCAN_PROFILES.get(
                next(
                    (
                        key
                        for key, value in SCAN_PROFILES.items()
                        if value["scan_type"] == scan_type
                    ),
                    "2",
                )
            )['name']}\n"
            f"[bold cyan]Nmap:[/bold cyan] {arguments}",
            title="AI-VulnScan",
            border_style="cyan",
        )
    )

    console.print(
        "[yellow]Starting Nmap scan...[/yellow]"
    )

    nm = nmap.PortScanner()

    try:
        nm.scan(
            hosts=target_ip,
            arguments=arguments,
        )

    except nmap.PortScannerError as e:
        console.print(
            f"[red]Nmap error:[/red] {e}"
        )
        return None

    except Exception as e:
        console.print(
            f"[red]Scan failed:[/red] {e}"
        )
        return None

    if target_ip not in nm.all_hosts():
        console.print(
            "[red]No scan results found.[/red]"
        )
        return None

    host = nm[target_ip]

    host_state = host.get(
        "status",
        {}
    ).get(
        "state",
        "unknown"
    )

    services = []

    for protocol in host.all_protocols():

        ports = host[protocol].keys()

        for port in sorted(ports):

            service = host[protocol][port]

            state = service.get(
                "state",
                ""
            )

            # Closed ports are not useful to the
            # vulnerability engine.
            if state == "closed":
                continue

            parsed = parse_service(
                port,
                protocol,
                service,
            )

            services.append(parsed)

    # OS information only exists when -O was used.
    os_results = parse_os(host)

    tcp_services = sum(
        1
        for service in services
        if service["protocol"] == "tcp"
    )

    udp_services = sum(
        1
        for service in services
        if service["protocol"] == "udp"
    )

    result = {
        "target": target_ip,

        "scan_type": scan_type,

        "status": "completed",

        "host_state": host_state,

        "os": os_results,

        "summary": {
            "total_services": len(services),
            "tcp_services": tcp_services,
            "udp_services": udp_services,
        },

        "services": services,
    }

    console.print()

    console.print(
        f"[green]Scan completed.[/green] "
        f"Open/filtered services discovered: "
        f"[bold]{len(services)}[/bold]"
    )

    return result


# ============================================================
# DISPLAY RESULTS
# ============================================================

def display_scan_table(services):

    if not services:
        console.print(
            "[yellow]No services discovered.[/yellow]"
        )
        return

    table = Table(
        title="Discovered Services",
        show_lines=True,
    )

    table.add_column(
        "Port",
        style="cyan",
    )

    table.add_column(
        "Proto",
        style="magenta",
    )

    table.add_column(
        "State",
        style="green",
    )

    table.add_column(
        "Service",
    )

    table.add_column(
        "Product",
    )

    table.add_column(
        "Version",
    )

    table.add_column(
        "Version Status",
    )

    table.add_column(
        "CPE",
    )

    for service in services:

        cpe = (
            ", ".join(service["cpe"])
            if service["cpe"]
            else "-"
        )

        table.add_row(
            str(service["port"]),
            service["protocol"],
            service["state"],
            service["service"] or "-",
            service["product"] or "-",
            service["version"] or "-",
            service["version_status"],
            cpe,
        )

    console.print(table)


# ============================================================
# SCAN PROFILE MENU
# ============================================================

def show_scan_profiles():

    console.print()

    console.print(
        Panel(
            "[bold cyan]Select Scan Profile[/bold cyan]",
            border_style="cyan",
        )
    )

    for number, profile in SCAN_PROFILES.items():

        recommended = ""

        if number == "2":
            recommended = " [bold green]★ Recommended[/bold green]"

        console.print(
            f"\n[bold yellow]{number}. "
            f"{profile['name']}[/bold yellow]"
            f"{recommended}"
        )

        console.print(
            f"   Description: "
            f"{profile['description']}"
        )

        console.print(
            f"   [bold cyan]When to use:[/bold cyan] "
            f"{profile['when_to_use']}"
        )

    console.print()


# ============================================================
# MAIN CLI
# ============================================================

if __name__ == "__main__":

    console.print(
        Panel(
            "[bold cyan]AI-VulnScan[/bold cyan]\n"
            "Network Vulnerability Scanner",
            border_style="cyan",
        )
    )

    # --------------------------------------------------------
    # Target
    # --------------------------------------------------------

    target = Prompt.ask(
        "\n[bold]Enter target IP/hostname[/bold]"
    )

    # --------------------------------------------------------
    # Scan profile
    # --------------------------------------------------------

    show_scan_profiles()

    choice = Prompt.ask(
        "Select scan profile",
        choices=list(SCAN_PROFILES.keys()),
        default="2",
    )

    selected_profile = SCAN_PROFILES[choice]

    scan_type = selected_profile["scan_type"]

    # --------------------------------------------------------
    # Advanced options
    # --------------------------------------------------------

    console.print()

    console.print(
        Panel(
            "[bold]Advanced Options[/bold]\n"
            "Press ENTER to use the default configuration.",
            border_style="blue",
        )
    )

    tcp_input = Prompt.ask(
        "Custom TCP ports "
        "(example: 22,80,443)",
        default="",
    )

    udp_input = ""

    if scan_type in ["deep", "udp", "full"]:
        udp_input = Prompt.ask(
            "Custom UDP ports "
            "(example: 53,123,161)",
            default="",
        )

    custom_tcp_ports = None
    custom_udp_ports = None

    if tcp_input.strip():

        try:
            custom_tcp_ports = [
                int(port.strip())
                for port in tcp_input.split(",")
                if port.strip()
            ]

        except ValueError:
            console.print(
                "[red]Invalid TCP port list.[/red]"
            )
            raise SystemExit(1)

    if udp_input.strip():

        try:
            custom_udp_ports = [
                int(port.strip())
                for port in udp_input.split(",")
                if port.strip()
            ]

        except ValueError:
            console.print(
                "[red]Invalid UDP port list.[/red]"
            )
            raise SystemExit(1)

    # --------------------------------------------------------
    # Show selected configuration
    # --------------------------------------------------------

    console.print()

    console.print(
        Panel(
            f"[bold]Selected Scan[/bold]\n\n"
            f"Profile: {selected_profile['name']}\n"
            f"When to use: {selected_profile['when_to_use']}\n"
            f"Target: {target}",
            title="Scan Configuration",
            border_style="green",
        )
    )

    # --------------------------------------------------------
    # Run scan
    # --------------------------------------------------------

    result = scan_target(
        target_ip=target,
        scan_type=scan_type,
        custom_tcp_ports=custom_tcp_ports,
        custom_udp_ports=custom_udp_ports,
    )

    if result is None:
        raise SystemExit(1)

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    display_scan_table(
        result["services"]
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    console.print()

    summary = result["summary"]

    console.print(
        Panel(
            f"[bold]Target:[/bold] {result['target']}\n"
            f"[bold]Host State:[/bold] {result['host_state']}\n"
            f"[bold]Total Services:[/bold] "
            f"{summary['total_services']}\n"
            f"[bold]TCP Services:[/bold] "
            f"{summary['tcp_services']}\n"
            f"[bold]UDP Services:[/bold] "
            f"{summary['udp_services']}",
            title="Scan Summary",
            border_style="green",
        )
    )