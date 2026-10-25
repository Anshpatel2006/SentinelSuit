import uvicorn
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.routes import router as ids_router
from app.core.detection_engine import DetectionEngine
from app.core.packet_capture import packet_capture_service
from app.database.db_manager import db_manager
from app.reporting.report_generator import report_generator

app = FastAPI(
    title=f"{settings.APP_NAME} - {settings.MODULE_NAME}",
    description="SentinelSuite Module 3: Network Intrusion Detection System (SentinelIDS)",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"]
)

app.include_router(ids_router, prefix=settings.API_PREFIX)

@app.on_event("startup")
async def startup_event():
    print(f"[*] Starting {settings.APP_NAME} - {settings.MODULE_NAME} (Port {settings.PORT})...")

@app.get("/health")
async def get_health():
    return {"status": "healthy", "service": "SentinelIDS", "module": settings.MODULE_NAME}

@app.post("/dashboard/capture/start")
async def dashboard_capture_start(interface: str = "", filter: str = ""):
    result = packet_capture_service.start_capture(interface=interface, filter_str=filter)
    return {
        "status": packet_capture_service.status,
        "live": packet_capture_service.status == "RUNNING",
        "details": result,
    }

@app.post("/dashboard/capture/stop")
async def dashboard_capture_stop():
    result = packet_capture_service.stop_capture()
    return {"status": "STOPPED", "live": False, "details": result}

@app.post("/dashboard/capture/toggle")
async def dashboard_capture_toggle(interface: str = "", filter: str = ""):
    if packet_capture_service.status == "RUNNING":
        result = packet_capture_service.stop_capture()
        return {"live": False, "status": "STOPPED", "action": "stopped"}
    else:
        result = packet_capture_service.start_capture(interface=interface, filter_str=filter)
        status = packet_capture_service.status
        return {
            "live": status == "RUNNING",
            "status": status,
            "action": "started" if status == "RUNNING" else "failed",
            "details": result,
        }

@app.get("/dashboard/capture-status")
async def get_dashboard_capture_status():
    is_live = (packet_capture_service.status == "RUNNING")
    recent = packet_capture_service.get_packets()
    last_pkt_time = recent[-1].get("timestamp") if recent else None
    age_seconds = (
        max(0.0, (datetime.utcnow() - last_pkt_time).total_seconds())
        if isinstance(last_pkt_time, datetime)
        else None
    )
    
    return {
        "live": is_live,
        "status": packet_capture_service.status,
        "packet_count": packet_capture_service.captured_packets_count,
        "last_packet_at": last_pkt_time,
        "age_seconds": age_seconds,
        "interface": packet_capture_service.interface or "default",
        "filter": packet_capture_service.filter
    }

@app.get("/dashboard/summary")
async def get_dashboard_summary():
    stats = db_manager.get_statistics()
    sev = stats.get("severity_distribution", {})
    return {
        "total_alerts": stats.get("total_alerts", 0),
        "critical_alerts": sev.get("CRITICAL", 0),
        "scan_count": stats.get("total_nmap_scans", 0),
        "total_flows": stats.get("total_flows", 0),
        "active_alerts": stats.get("active_alerts", 0)
    }

@app.get("/dashboard/recent-alerts")
async def get_dashboard_recent_alerts():
    raw_alerts = db_manager.get_history(limit=50)
    formatted = []
    for a in raw_alerts:
        item = dict(a)
        item["attack_name"] = a.get("attack_type", "Unknown Anomaly")
        item["attack"] = a.get("attack_type", "Unknown Anomaly")
        item["source_ip"] = f"{a.get('src_ip')}:{a.get('src_port')}" if a.get("src_port") else a.get("src_ip", "-")
        item["destination_ip"] = f"{a.get('dst_ip')}:{a.get('dst_port')}" if a.get("dst_port") else a.get("dst_ip", "-")
        item["severity"] = a.get("severity", "LOW")
        item["risk_score"] = a.get("risk_score", 0.0)
        item["protocol"] = a.get("protocol", "TCP")
        formatted.append(item)
    return formatted

@app.get("/dashboard/full-report/pdf")
@app.get("/dashboard/report.pdf")
async def download_dashboard_report_pdf():
    rep = report_generator.generate_report(export_pdf=True)
    pdf_file = rep.get("pdf_path")
    filename = f"SentinelIDS-Security-Report-{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return FileResponse(path=pdf_file, filename=filename, media_type="application/pdf")

@app.get("/dashboard/full-report")
async def get_dashboard_full_report(format: str = Query("pdf")):
    if format == "pdf":
        return await download_dashboard_report_pdf()
    stats = db_manager.get_statistics()
    alerts = db_manager.get_history(limit=500)
    return {"platform": settings.APP_NAME, "summary": stats, "alerts": alerts}

@app.get("/")
async def root():
    return {"platform": settings.APP_NAME, "module": settings.MODULE_NAME, "status": "OPERATIONAL"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
