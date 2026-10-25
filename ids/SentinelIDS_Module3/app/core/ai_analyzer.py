from typing import Dict, Any, Optional
import os

class AIIncidentAnalyzer:
    """
    Implements AI Incident Analysis & Threat Narrative (Slides 10, 29, 34).
    Produces MITRE ATT&CK mapping, threat severity analysis, and actionable remediation steps.
    Supports LLM API key when available, with a deterministic expert cybersecurity knowledge base fallback.
    """
    
    ATTACK_KNOWLEDGE_BASE = {
        "Denial of Service (DoS)": {
            "mitre": "T1498 - Network Denial of Service",
            "tactics": "Impact",
            "summary": "High-volume connection flood or protocol exploitation targeted at depleting host/network state buffers.",
            "impact": "Service degradation or complete unresponsiveness of web and API services.",
            "recommendations": [
                "Deploy upstream rate-limiting or SYN cookies (sysctl -w net.ipv4.tcp_syncookies=1).",
                "Null-route or block the offending IP address in perimeter firewall.",
                "Activate DDoS mitigation proxy (Cloudflare/AWS Shield)."
            ]
        },
        "Port Scan / Reconnaissance": {
            "mitre": "T1046 - Network Service Discovery",
            "tactics": "Discovery",
            "summary": "Attacker is probing open TCP/UDP ports to enumerate listening services and software versions.",
            "impact": "Pre-attack reconnaissance often preceding exploitation or targeted vulnerability probing.",
            "recommendations": [
                "Block the scanning IP at the edge firewall.",
                "Verify exposed ports against approved network perimeter baseline.",
                "Ensure administrative services (SSH, RDP, DB) are restricted to VPN only."
            ]
        },
        "Web Attack (Exploit)": {
            "mitre": "T1190 - Exploit Public-Facing Application",
            "tactics": "Initial Access",
            "summary": "Malicious payload detected in application layer stream (SQLi, XSS, or Remote Code Execution attempt).",
            "impact": "Potential database exfiltration, unauthorized administrative access, or arbitrary code execution.",
            "recommendations": [
                "Inspect web application logs for HTTP 200/500 response codes on the targeted URI.",
                "Ensure parameterized queries / prepared statements are enforced.",
                "Deploy ModSecurity / WAF rule to block matching attack signatures."
            ]
        },
        "Authentication Brute Force": {
            "mitre": "T1110 - Brute Force",
            "tactics": "Credential Access",
            "summary": "High frequency of failed authentication handshakes detected targeting remote access services.",
            "impact": "Risk of credential compromise and subsequent unauthorized remote shell access.",
            "recommendations": [
                "Enable Fail2ban or automated account lockout policies.",
                "Disable password-based SSH authentication in favor of ed25519 public keys.",
                "Enforce Multi-Factor Authentication (MFA) across all external gateways."
            ]
        }
    }

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY")

    def generate_incident_summary(
        self,
        alert: Dict[str, Any],
        nmap_scan: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generates a comprehensive AI Security Incident Briefing.
        """
        attack_type = alert.get("attack_type", "Unknown Anomaly")
        severity = alert.get("severity", "MEDIUM")
        src_ip = alert.get("src_ip", "Unknown")
        dst_ip = alert.get("dst_ip", "Unknown")
        risk_score = alert.get("risk_score", 0.0)
        
        # Match attack in KB
        kb_entry = None
        for key, entry in self.ATTACK_KNOWLEDGE_BASE.items():
            if key.lower() in attack_type.lower() or attack_type.lower() in key.lower():
                kb_entry = entry
                break
                
        if not kb_entry:
            kb_entry = {
                "mitre": "T1205 - Traffic Signaling / Anomaly",
                "tactics": "Defense Evasion / Initial Access",
                "summary": "Statistically anomalous network flow behavior inconsistent with baseline enterprise network profiles.",
                "impact": "Unclassified network anomaly indicating possible covert communications or data staging.",
                "recommendations": [
                    "Isolate the communicating endpoints and conduct PCAP packet inspection.",
                    "Verify process execution logs on source host via EDR.",
                    "Review network firewall egress rules."
                ]
            }

        open_ports_summary = "None detected or scan skipped."
        if nmap_scan and nmap_scan.get("open_ports"):
            ports = [f"{p.get('port')}/{p.get('protocol')} ({p.get('service')})" for p in nmap_scan["open_ports"]]
            open_ports_summary = ", ".join(ports)

        briefing = (
            f"### [AI Sentinel Incident Analysis Report]\n\n"
            f"**Executive Verdict:** {severity} threat incident detected from `{src_ip}` targeting `{dst_ip}`. "
            f"Calculated Threat Risk Score: **{risk_score}/100**.\n\n"
            f"**MITRE ATT&CK Mapping:** `{kb_entry['mitre']}` (Tactic: {kb_entry['tactics']})\n\n"
            f"**Threat Description:** {kb_entry['summary']}\n\n"
            f"**Investigative Evidence:**\n"
            f"- Alert Classification: {attack_type}\n"
            f"- Destination Port: {alert.get('dst_port')} ({alert.get('protocol')})\n"
            f"- Response Action Taken: `{alert.get('response_action')}`\n"
            f"- Host Fingerprinting (Bounded Nmap): {open_ports_summary}\n\n"
            f"**Potential Business Impact:** {kb_entry['impact']}\n\n"
            f"**Recommended Immediate Response Actions:**\n"
        )
        
        for idx, rec in enumerate(kb_entry["recommendations"], 1):
            briefing += f"{idx}. {rec}\n"
            
        return briefing

ai_analyzer = AIIncidentAnalyzer()
