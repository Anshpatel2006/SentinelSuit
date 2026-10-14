from fastapi import APIRouter, HTTPException
from api.routes.dashboard import recent_alerts as get_recent_alerts

from api.services import (
    get_alerts,
    get_high_alerts,
    get_decisions,
    get_scans,
    get_reports,
    get_dashboard_summary,
    get_analytics
)

from api.models import (
    AlertModel,
    DecisionModel,
    ScanModel,
    AIReportModel,
    DashboardSummaryModel,
    AnalyticsModel
)

router = APIRouter()


# ============================================================
# HEALTH CHECK
# ============================================================

@router.get("/")
def home():
    return {
        "application": "SentinelIDS",
        "version": "1.0",
        "status": "Running"
    }


# ============================================================
# DASHBOARD
# ============================================================

@router.get(
    "/dashboard/summary",
    response_model=DashboardSummaryModel
)
def dashboard_summary():
    return get_dashboard_summary()


# ============================================================
# ALERTS
# ============================================================

@router.get(
    "/alerts",
    response_model=list[AlertModel]
)
def alerts():
    return get_alerts()


@router.get("/dashboard/recent-alerts")
def dashboard_recent_alerts():
    """Return the latest live alerts for the unified dashboard."""
    return get_recent_alerts()


@router.get(
    "/alerts/high",
    response_model=list[AlertModel]
)
def high_alerts():
    return get_high_alerts()


# ============================================================
# DECISIONS
# ============================================================

@router.get(
    "/decisions",
    response_model=list[DecisionModel]
)
def decisions():
    return get_decisions()


# ============================================================
# SCAN RESULTS
# ============================================================

@router.get(
    "/scans",
    response_model=list[ScanModel]
)
def scans():
    return get_scans()


# ============================================================
# AI REPORTS
# ============================================================

@router.get(
    "/reports",
    response_model=list[AIReportModel]
)
def reports():
    return get_reports()


@router.get(
    "/reports/{report_index}",
    response_model=AIReportModel
)
def report_details(report_index: int):

    reports = get_reports()

    if report_index < 0 or report_index >= len(reports):
        raise HTTPException(
            status_code=404,
            detail="Report not found."
        )

    return reports[report_index]


# ============================================================
# ANALYTICS
# ============================================================

@router.get(
    "/analytics",
    response_model=AnalyticsModel
)
def analytics():
    return get_analytics()
