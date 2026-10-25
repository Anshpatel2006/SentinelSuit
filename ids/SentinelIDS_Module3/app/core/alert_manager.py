from datetime import datetime
from typing import Dict, Any, List, Optional
import logging
import requests
from app.config import settings
from app.database.db_manager import db_manager
from app.core.nmap_scanner import nmap_scanner
from app.core.ai_analyzer import ai_analyzer

logger = logging.getLogger("SentinelIDS.AlertManager")

class Alert:
    """
    Corresponds directly to Alert in Slide 31 Class Diagram:
    - id: int
    - timestamp: datetime
    - severity: str
    - attack_type: str
    - src_ip: str
    - dst_ip: str
    - details: str
    - status: str
    - set_severity()
    - set_status()
    - add_details()
    - to_dict()
    """
    def __init__(
        self,
        alert_id: int = 0,
        severity: str = "LOW",
        attack_type: str = "Unknown Anomaly",
        src_ip: str = "0.0.0.0",
        dst_ip: str = "0.0.0.0",
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "TCP",
        risk_score: float = 0.0,
        response_action: str = "LOG",
        details: str = "",
        status: str = "NEW",
        timestamp: Optional[datetime] = None
    ):
        self.id: int = alert_id
        self.timestamp: datetime = timestamp or datetime.utcnow()
        self.severity: str = severity
        self.attack_type: str = attack_type
        self.src_ip: str = src_ip
        self.dst_ip: str = dst_ip
        self.src_port: int = src_port
        self.dst_port: int = dst_port
        self.protocol: str = protocol
        self.risk_score: float = risk_score
        self.response_action: str = response_action
        self.details: str = details
        self.status: str = status
        
        self.nmap_scan_id: Optional[int] = None
        self.ai_summary: Optional[str] = None
        self.raw_evidence: Optional[Dict[str, Any]] = None

    def set_severity(self, severity: str):
        self.severity = severity.upper()

    def set_status(self, status: str):
        self.status = status.upper()

    def add_details(self, details: str):
        if self.details:
            self.details += f" | {details}"
        else:
            self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "attack_type": self.attack_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "risk_score": self.risk_score,
            "response_action": self.response_action,
            "details": self.details,
            "status": self.status,
            "nmap_scan_id": self.nmap_scan_id,
            "ai_summary": self.ai_summary,
            "raw_evidence": self.raw_evidence
        }


class AlertManager:
    """
    Corresponds directly to AlertManager in Slide 31 Class Diagram:
    - id: int
    - notification_type: str
    - channels: list
    - enabled: bool
    - send_alert(alert)
    - send_email(subject, body, to)
    - send_notification(channel, message)
    - update_config(config_dict)
    """
    def __init__(self):
        self.id: int = 1
        self.notification_type: str = "Multi-Channel Security Alert Dispatcher"
        self.channels: List[str] = ["DASHBOARD", "LOG", "WEBHOOK"]
        self.enabled: bool = True
        self.webhook_url: str = settings.ALERT_WEBHOOK_URL
        self.email_enabled: bool = settings.EMAIL_NOTIFICATIONS_ENABLED

    def send_alert(self, alert_input: Any) -> Dict[str, Any]:
        """
        Processes alert, triggers bounded automated Nmap and AI analysis if required,
        and saves to database.
        """
        if not self.enabled:
            return {}

        # Handle either Alert object or dictionary
        if isinstance(alert_input, dict):
            alert = Alert(
                severity=alert_input.get("severity", "LOW"),
                attack_type=alert_input.get("attack_type", "Unknown Anomaly"),
                src_ip=alert_input.get("src_ip", "0.0.0.0"),
                dst_ip=alert_input.get("dst_ip", "0.0.0.0"),
                src_port=alert_input.get("src_port", 0),
                dst_port=alert_input.get("dst_port", 0),
                protocol=alert_input.get("protocol", "TCP"),
                risk_score=alert_input.get("risk_score", 0.0),
                response_action=alert_input.get("response_action", "LOG"),
                details=alert_input.get("details", ""),
                status=alert_input.get("status", "NEW")
            )
            alert.raw_evidence = alert_input.get("raw_evidence")
        else:
            alert = alert_input

        # Automated Response: Trigger Bounded Nmap Scan for High or Critical threats
        scan_record = None
        if alert.response_action in ["SCAN", "SCAN_AND_AI"] and settings.AUTO_TRIGGER_NMAP_ON_HIGH_RISK:
            logger.info(f"Triggering Bounded Nmap Scan for target: {alert.src_ip}")
            scan_res = nmap_scanner.run_scan(alert.src_ip)
            scan_record = db_manager.save_scan(scan_res)
            alert.nmap_scan_id = scan_record["id"]

        # Automated Response: Trigger AI Incident Analysis for Critical threats
        if alert.response_action == "SCAN_AND_AI" and settings.AUTO_TRIGGER_AI_ON_CRITICAL:
            logger.info(f"Generating AI Incident Briefing for Alert {alert.attack_type}")
            alert.ai_summary = ai_analyzer.generate_incident_summary(alert.to_dict(), scan_res if scan_record else None)

        # Save to Database
        saved_alert = db_manager.save_alert(alert.to_dict())
        alert.id = saved_alert["id"]

        # Dispatch notifications across channels
        self.send_notification("LOG", f"[{alert.severity}] {alert.attack_type} from {alert.src_ip}:{alert.src_port} -> {alert.dst_ip}:{alert.dst_port}")
        
        if self.webhook_url and "WEBHOOK" in self.channels:
            try:
                requests.post(self.webhook_url, json=saved_alert, timeout=3.0)
            except Exception as e:
                logger.warning(f"Failed to deliver webhook notification: {e}")

        return saved_alert

    def send_email(self, subject: str, body: str, to: str) -> bool:
        """Mock or SMTP email sender"""
        logger.info(f"[EMAIL ALERT] To: {to} | Subject: {subject}\n{body}")
        return True

    def send_notification(self, channel: str, message: str) -> bool:
        """Dispatches notification to specified channel"""
        if channel == "LOG":
            logger.warning(f"[SENTINEL IDS ALERT] {message}")
            return True
        elif channel == "DASHBOARD":
            # Handled via DB polling / WebSockets
            return True
        return False

    def update_config(self, config_dict: Dict[str, Any]):
        """Updates channels and notification configuration dynamically"""
        if "channels" in config_dict:
            self.channels = config_dict["channels"]
        if "enabled" in config_dict:
            self.enabled = bool(config_dict["enabled"])
        if "webhook_url" in config_dict:
            self.webhook_url = config_dict["webhook_url"]
        if "email_enabled" in config_dict:
            self.email_enabled = bool(config_dict["email_enabled"])

alert_manager = AlertManager()
