import os
import shutil
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File, Query, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.core.packet_capture import packet_capture_service
from app.core.nmap_scanner import nmap_scanner
from app.core.ai_analyzer import ai_analyzer
from app.database.db_manager import db_manager
from app.reporting.report_generator import report_generator

router = APIRouter()

# --- Request / Response Schemas ---
class StartCaptureRequest(BaseModel):
    interface: Optional[str] = Field("", description="Network interface name (leave empty for default)")
    filter: Optional[str] = Field("", description="BPF capture filter (e.g. 'tcp', 'port 80')")
    duration: Optional[int] = Field(None, description="Auto-stop duration in seconds")

class UpdateAlertStatusRequest(BaseModel):
    status: str = Field(..., description="NEW, INVESTIGATING, RESOLVED, or DISMISSED")
    note: Optional[str] = Field(None, description="Optional analyst triage notes")

class TriggerScanRequest(BaseModel):
    target_ip: str = Field(..., description="Target IP address for bounded Nmap scan")

# --- Capture Endpoints (Slide 30, 31, 38) ---
@router.post("/packet/start", summary="Start live network packet capture")
async def start_capture(req: StartCaptureRequest):
    """Corresponds to BackendAPI.start_capture() in Slide 31"""
    result = packet_capture_service.start_capture(
        interface=req.interface or "",
        filter_str=req.filter or "",
        duration=req.duration
    )
    return result

@router.post("/packet/stop", summary="Stop live network packet capture")
async def stop_capture():
    """Corresponds to BackendAPI.stop_capture() in Slide 31"""
    result = packet_capture_service.stop_capture()
    return result

@router.get("/packet/status", summary="Get live capture engine status and telemetry")
async def get_capture_status():
    """Corresponds to BackendAPI.get_status() in Slide 31"""
    return {
        "status": packet_capture_service.status,
        "interface": packet_capture_service.interface or "Default",
        "filter": packet_capture_service.filter,
        "captured_packets": packet_capture_service.captured_packets_count,
        "analyzed_flows": packet_capture_service.analyzed_flows_count,
        "recent_packets_sample": packet_capture_service.get_packets()[-10:]
    }

@router.get("/packet/interfaces", summary="List available host network interfaces")
async def list_interfaces():
    interfaces = packet_capture_service.get_interfaces()
    return {"interfaces": interfaces}

@router.post("/packet/upload", summary="Upload PCAP file for offline deep flow analysis")
async def upload_pcap(file: UploadFile = File(...)):
    """Accepts PCAP / PCAPNG upload and runs through SentinelIDS pipeline"""
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .pcap or .pcapng files are supported.")

    temp_path = settings.CAPTURES_DIR / f"upload_{file.filename}"
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        analysis_result = packet_capture_service.process_pcap(str(temp_path))
        return {
            "message": "PCAP analysis completed successfully",
            "filename": file.filename,
            "results": analysis_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process PCAP: {str(e)}")

# --- Alert Management Endpoints (Slide 31, 38) ---
@router.get("/ids/alerts", summary="Get paginated security alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, description="Filter by LOW, MEDIUM, HIGH, CRITICAL"),
    attack_type: Optional[str] = Query(None, description="Filter by attack keyword")
):
    """Corresponds to BackendAPI.get_alerts() in Slide 31"""
    alerts = db_manager.get_history(limit=limit, offset=offset, severity=severity, attack_type=attack_type)
    return {"count": len(alerts), "alerts": alerts}

@router.get("/ids/alerts/{alert_id}", summary="Get detailed information for a specific alert")
async def get_alert_detail(alert_id: int):
    alert = db_manager.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/ids/alerts/{alert_id}/status", summary="Update alert triage status")
async def update_alert_status(alert_id: int, req: UpdateAlertStatusRequest):
    updates = {"status": req.status.upper()}
    if req.note:
        existing = db_manager.get_alert_by_id(alert_id)
        if existing:
            current_details = existing.get("details", "")
            updates["details"] = f"{current_details} | [Triage Note]: {req.note}"
            
    updated = db_manager.update_alert(alert_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return updated

# --- Security Analytics & Dashboard Stats (Slide 31, 36) ---
@router.get("/ids/stats", summary="Get real-time security posture and threat statistics")
async def get_statistics():
    return db_manager.get_statistics()

# --- Reporting Endpoints (Slide 31, 38) ---
@router.post("/ids/report/generate", summary="Generate a threat assessment incident report")
async def generate_report(export_pdf: bool = True):
    """Corresponds to BackendAPI.get_reports() in Slide 31"""
    result = report_generator.generate_report(export_pdf=export_pdf)
    return result

@router.get("/ids/report/download/{report_id}", summary="Download generated PDF or JSON report")
async def download_report(report_id: str, format: str = Query("pdf", regex="^(pdf|json|html)$")):
    file_path = settings.REPORTS_DIR / f"{report_id}.{format}"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    
    media_type = "application/pdf" if format == "pdf" else ("application/json" if format == "json" else "text/html")
    return FileResponse(path=str(file_path), filename=f"{report_id}.{format}", media_type=media_type)

# --- Bounded Nmap & AI Threat Analysis Endpoints (Slide 10, 34) ---
@router.post("/ids/scan", summary="Trigger a bounded Nmap scan against an IP")
async def trigger_bounded_nmap_scan(req: TriggerScanRequest):
    """Executes strictly bounded Nmap scan: -Pn -sV -sC --top-ports 20"""
    scan_result = nmap_scanner.run_scan(req.target_ip)
    saved_record = db_manager.save_scan(scan_result)
    return saved_record

@router.post("/ids/ai/summary", summary="Generate AI threat analysis narrative for an alert")
async def generate_ai_threat_summary(alert_id: int):
    alert = db_manager.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    summary = ai_analyzer.generate_incident_summary(alert)
    db_manager.update_alert(alert_id, {"ai_summary": summary})
    return {"alert_id": alert_id, "ai_summary": summary}
