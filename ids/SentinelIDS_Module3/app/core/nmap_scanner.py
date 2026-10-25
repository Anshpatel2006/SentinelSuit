import shutil
import subprocess
import socket
from datetime import datetime
from typing import Dict, Any, List
from app.config import settings

class NmapScanner:
    """
    Implements Bounded Nmap Scanner (Slides 10, 11, 34).
    Flags: -Pn -sV -sC --top-ports 20
    Strictly bounded by execution timeout to prevent hanging.
    Includes graceful socket-based fallback if nmap binary is absent.
    """
    TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
    PORT_SERVICES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
        80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap", 443: "https",
        445: "microsoft-ds (smb)", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
        1521: "oracle", 3306: "mysql", 3389: "ms-wbt-server (rdp)", 5432: "postgresql",
        8080: "http-proxy", 8443: "https-alt"
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout or settings.NMAP_TIMEOUT_SECONDS
        self.nmap_path = shutil.which("nmap")

    def run_scan(self, target_ip: str) -> Dict[str, Any]:
        """
        Executes bounded scan against suspicious IP address.
        """
        start_time = datetime.utcnow()
        command = f"nmap {settings.NMAP_DEFAULT_FLAGS} {target_ip}"
        
        # Don't scan non-routable / dummy IPs
        if target_ip in ["0.0.0.0", "255.255.255.255"]:
            return {
                "target_ip": target_ip,
                "command": command,
                "start_time": start_time,
                "end_time": datetime.utcnow(),
                "status": "SKIPPED",
                "open_ports": [],
                "raw_output": f"Skipped non-routable target {target_ip}",
                "risk_assessment": "Invalid target IP address"
            }

        # If native nmap is available
        if self.nmap_path:
            return self._run_native_nmap(target_ip, command, start_time)
        else:
            return self._run_socket_fallback(target_ip, command, start_time)

    def _run_native_nmap(self, target_ip: str, command: str, start_time: datetime) -> Dict[str, Any]:
        cmd_args = ["nmap", "-Pn", "-sV", "-sC", "--top-ports", "20", target_ip]
        try:
            res = subprocess.run(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout
            )
            raw_output = res.stdout or res.stderr
            open_ports = self._parse_nmap_text(raw_output)
            
            return {
                "target_ip": target_ip,
                "command": command,
                "start_time": start_time,
                "end_time": datetime.utcnow(),
                "status": "COMPLETED",
                "open_ports": open_ports,
                "raw_output": raw_output,
                "risk_assessment": f"Discovered {len(open_ports)} exposed ports via native Nmap scan."
            }
        except subprocess.TimeoutExpired:
            return {
                "target_ip": target_ip,
                "command": command,
                "start_time": start_time,
                "end_time": datetime.utcnow(),
                "status": "TIMEOUT",
                "open_ports": [],
                "raw_output": f"Scan timed out after {self.timeout} seconds.",
                "risk_assessment": "Target unresponsive or scan throttled."
            }
        except Exception as e:
            return self._run_socket_fallback(target_ip, command, start_time, error_reason=str(e))

    def _run_socket_fallback(self, target_ip: str, command: str, start_time: datetime, error_reason: str = "") -> Dict[str, Any]:
        """Fast threaded/socket scanner fallback when nmap binary is missing"""
        open_ports = []
        raw_lines = [
            f"# SentinelIDS Embedded Bounded Scanner (Fallback Mode)",
            f"# Target: {target_ip}",
            f"# Command equivalent: {command}",
            f"# Note: Native nmap was unavailable ({error_reason or 'Binary not found in PATH'}). Used bounded socket probe.",
            f"PORT     STATE SERVICE"
        ]

        # Scan top 20 ports with short timeouts
        for port in self.TOP_20_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    svc = self.PORT_SERVICES.get(port, "unknown")
                    open_ports.append({"port": port, "protocol": "tcp", "state": "open", "service": svc})
                    raw_lines.append(f"{port}/tcp  open  {svc}")
            except Exception:
                pass
            finally:
                s.close()

        if not open_ports:
            raw_lines.append("All 20 scanned ports are closed or filtered.")

        risk = f"Identified {len(open_ports)} open listening services." if open_ports else "No common services exposed."

        return {
            "target_ip": target_ip,
            "command": command,
            "start_time": start_time,
            "end_time": datetime.utcnow(),
            "status": "COMPLETED_FALLBACK",
            "open_ports": open_ports,
            "raw_output": "\n".join(raw_lines),
            "risk_assessment": risk
        }

    def _parse_nmap_text(self, output: str) -> List[Dict[str, Any]]:
        """Parses port lines from standard nmap stdout"""
        open_ports = []
        for line in output.splitlines():
            line = line.strip()
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "open":
                    port_proto = parts[0].split("/")
                    open_ports.append({
                        "port": int(port_proto[0]),
                        "protocol": port_proto[1],
                        "state": "open",
                        "service": parts[2],
                        "version": " ".join(parts[3:]) if len(parts) > 3 else ""
                    })
        return open_ports

# Global scanner instance
nmap_scanner = NmapScanner()
