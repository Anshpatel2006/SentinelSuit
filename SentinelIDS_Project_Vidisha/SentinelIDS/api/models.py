from pydantic import BaseModel
from typing import List, Dict, Any


# ============================================================
# ALERT MODEL
# ============================================================

class AlertModel(BaseModel):
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None = None
    destination_port: int | None = None

    attack_name: str
    detection_method: str

    severity: str
    risk_score: int

    ml_prediction: str
    ml_confidence: float

    signature_alert: List[Dict[str, Any]] = []


# ============================================================
# DECISION MODEL
# ============================================================

class DecisionModel(BaseModel):
    timestamp: float
    source_ip: str
    destination_ip: str

    protocol: str
    source_port: int | None = None
    destination_port: int | None = None

    attack_name: str
    category: str

    severity: str
    risk_score: int

    action: str

    ml_prediction: str
    ml_confidence: float


# ============================================================
# SCAN RESULT MODEL
# ============================================================

class ScanModel(BaseModel):
    timestamp: float

    attack_name: str
    category: str

    source_ip: str
    target_ip: str

    protocol: str
    destination_port: int | None = None

    severity: str
    risk_score: int

    scan_status: str
    scan_output: str


# ============================================================
# AI REPORT MODEL
# ============================================================

class AIReportModel(BaseModel):
    timestamp: float

    attack_name: str
    category: str

    source_ip: str
    destination_ip: str

    protocol: str

    severity: str
    risk_score: int

    action: str

    analysis: Dict[str, Any]


# ============================================================
# DASHBOARD SUMMARY MODEL
# ============================================================

class DashboardSummaryModel(BaseModel):
    total_alerts: int
    high_alerts: int
    critical_alerts: int

    scan_count: int
    report_count: int

    severity_distribution: Dict[str, int]
    attack_distribution: Dict[str, int]
    protocol_distribution: Dict[str, int]


# ============================================================
# ANALYTICS MODEL
# ============================================================

class AnalyticsModel(BaseModel):
    attacks: Dict[str, int]
    severity: Dict[str, int]
    protocols: Dict[str, int]
    risk_scores: List[int]
