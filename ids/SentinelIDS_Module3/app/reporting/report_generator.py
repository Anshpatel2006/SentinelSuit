import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from app.config import settings
from app.database.db_manager import db_manager

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

class ReportGenerator:
    """
    Corresponds directly to ReportGenerator in Slide 31 Class Diagram:
    - id: int
    - report_type: str
    - format: str
    - template_path: str
    - generate_report(report_id, alerts, stats)
    - create_pdf(report_data, output_path)
    - create_json(report_data, output_path)
    - get_statistics()
    """
    def __init__(self):
        self.id: int = 1
        self.report_type: str = "Network Intrusion & Threat Assessment Report"
        self.format: str = "PDF / JSON"
        self.template_path: str = str(settings.REPORTS_DIR)

    def get_statistics(self) -> Dict[str, Any]:
        """Fetches latest system statistics from DatabaseManager"""
        return db_manager.get_statistics()

    def generate_report(
        self,
        report_id: Optional[str] = None,
        alerts: Optional[List[Dict[str, Any]]] = None,
        stats: Optional[Dict[str, Any]] = None,
        export_pdf: bool = True
    ) -> Dict[str, Any]:
        """
        Orchestrates full report generation in JSON and PDF formats.
        """
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        rep_id = report_id or f"REPORT_M3_{timestamp_str}"
        
        alerts_list = alerts if alerts is not None else db_manager.get_history(limit=100)
        system_stats = stats if stats is not None else self.get_statistics()

        report_data = {
            "report_id": rep_id,
            "generated_at": datetime.utcnow().isoformat(),
            "module": settings.MODULE_NAME,
            "platform": settings.APP_NAME,
            "summary": {
                "total_alerts": len(alerts_list),
                "severity_distribution": system_stats.get("severity_distribution", {}),
                "top_attackers": system_stats.get("top_attackers", []),
                "active_alerts": system_stats.get("active_alerts", 0),
                "total_flows_monitored": system_stats.get("total_flows", 0)
            },
            "alerts": alerts_list
        }

        # Save JSON Report
        json_path = settings.REPORTS_DIR / f"{rep_id}.json"
        self.create_json(report_data, str(json_path))

        # Save PDF Report
        pdf_path = settings.REPORTS_DIR / f"{rep_id}.pdf"
        pdf_created = False
        if export_pdf:
            pdf_created = self.create_pdf(report_data, str(pdf_path))

        return {
            "report_id": rep_id,
            "json_path": str(json_path),
            "pdf_path": str(pdf_path) if pdf_created else None,
            "summary": report_data["summary"],
            "alerts_count": len(alerts_list)
        }

    def create_json(self, report_data: Dict[str, Any], output_path: str) -> str:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return output_path

    def create_pdf(self, report_data: Dict[str, Any], output_path: str) -> bool:
        """Renders comprehensive PDF report with threat tables and AI findings"""
        if not REPORTLAB_AVAILABLE:
            # Fallback to HTML/Markdown if ReportLab is missing
            html_path = output_path.replace(".pdf", ".html")
            self._create_html_fallback(report_data, html_path)
            return False

        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36
            )
            styles = getSampleStyleSheet()
            
            # Custom Styles
            title_style = ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontSize=20,
                leading=24,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=6
            )
            subtitle_style = ParagraphStyle(
                'Subtitle',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor("#475569"),
                spaceAfter=15
            )
            h2_style = ParagraphStyle(
                'H2',
                parent=styles['Heading2'],
                fontSize=14,
                leading=18,
                textColor=colors.HexColor("#1e293b"),
                spaceBefore=10,
                spaceAfter=8
            )
            body_style = ParagraphStyle(
                'Body',
                parent=styles['Normal'],
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#334155")
            )

            story = []

            # Header
            story.append(Paragraph(f"<b>SentinelSuite — SentinelIDS Incident Report</b>", title_style))
            story.append(Paragraph(
                f"Report ID: <code>{report_data['report_id']}</code> | Generated: {report_data['generated_at']} UTC | Environment: Production Network",
                subtitle_style
            ))
            story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=12))

            # Executive Summary Section
            story.append(Paragraph("1. Executive Threat Summary", h2_style))
            summary_info = report_data["summary"]
            sev = summary_info.get("severity_distribution", {})
            
            summary_table_data = [
                ["Total Alerts", "Critical", "High", "Medium", "Low", "Flows Monitored"],
                [
                    str(summary_info.get("total_alerts", 0)),
                    str(sev.get("CRITICAL", 0)),
                    str(sev.get("HIGH", 0)),
                    str(sev.get("MEDIUM", 0)),
                    str(sev.get("LOW", 0)),
                    str(summary_info.get("total_flows_monitored", 0))
                ]
            ]
            summary_table = Table(summary_table_data, colWidths=[80, 80, 80, 80, 80, 140])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 14))

            # Alert Evidence Log Section
            story.append(Paragraph("2. Detected Network Security Incidents", h2_style))
            alerts = report_data.get("alerts", [])
            
            if not alerts:
                story.append(Paragraph("No intrusion events or anomalies recorded in the selected period.", body_style))
            else:
                alert_table_data = [
                    ["Time", "Severity", "Attack Type", "Source IP", "Target", "Risk Score", "Action"]
                ]
                for a in alerts[:25]:  # Top 25 alerts for PDF readability
                    alert_table_data.append([
                        a.get("timestamp", "")[:19].replace("T", " "),
                        a.get("severity", "LOW"),
                        a.get("attack_type", "")[:24],
                        f"{a.get('src_ip')}:{a.get('src_port')}",
                        f"{a.get('dst_ip')}:{a.get('dst_port')}",
                        f"{a.get('risk_score', 0)}/100",
                        a.get("response_action", "LOG")
                    ])
                
                alert_table = Table(alert_table_data, colWidths=[95, 55, 120, 95, 95, 50, 40])
                alert_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                    ('ALIGN', (5, 0), (6, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ]))
                story.append(alert_table)

            story.append(Spacer(1, 15))

            # AI Briefing & Recommendations
            story.append(Paragraph("3. AI Threat Intelligence & Recommended Mitigations", h2_style))
            critical_alerts = [a for a in alerts if a.get("ai_summary")]
            if critical_alerts:
                for ca in critical_alerts[:3]:
                    story.append(Paragraph(f"<b>Incident Analysis: {ca.get('attack_type')} (Source: {ca.get('src_ip')})</b>", body_style))
                    clean_ai = ca.get("ai_summary", "").replace("#", "").replace("**", "")
                    story.append(Paragraph(clean_ai.replace("\n", "<br/>"), body_style))
                    story.append(Spacer(1, 10))
            else:
                story.append(Paragraph(
                    "Standard incident triage procedure: Block repeat offending IP addresses at edge firewalls, inspect application server access logs for anomalous payloads, and enforce rate-limiting.",
                    body_style
                ))

            doc.build(story)
            return True
        except Exception as e:
            # Fallback
            html_path = output_path.replace(".pdf", ".html")
            self._create_html_fallback(report_data, html_path)
            return False

    def _create_html_fallback(self, report_data: Dict[str, Any], output_path: str):
        """Generates clean HTML report if PDF compilation is not possible"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SentinelIDS Incident Report - {report_data['report_id']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #1e293b; }}
        .header {{ border-bottom: 2px solid #2563eb; padding-bottom: 15px; margin-bottom: 25px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
        th {{ background: #0f172a; color: white; }}
        .CRITICAL {{ color: #dc2626; font-weight: bold; }}
        .HIGH {{ color: #ea580c; font-weight: bold; }}
        .MEDIUM {{ color: #d97706; }}
        .LOW {{ color: #16a34a; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SentinelSuite — SentinelIDS Incident Report</h1>
        <p>Report ID: {report_data['report_id']} | Generated: {report_data['generated_at']} UTC</p>
    </div>
    <h2>1. Threat Overview</h2>
    <p>Total Alerts: <b>{report_data['summary']['total_alerts']}</b> | Monitored Flows: <b>{report_data['summary']['total_flows_monitored']}</b></p>
    <h2>2. Alerts Log</h2>
    <table>
        <tr><th>Timestamp</th><th>Severity</th><th>Attack Type</th><th>Source</th><th>Target</th><th>Risk</th><th>Action</th></tr>
        {''.join([f"<tr><td>{a.get('timestamp','')}</td><td class='{a.get('severity')}'>{a.get('severity')}</td><td>{a.get('attack_type')}</td><td>{a.get('src_ip')}:{a.get('src_port')}</td><td>{a.get('dst_ip')}:{a.get('dst_port')}</td><td>{a.get('risk_score')}/100</td><td>{a.get('response_action')}</td></tr>" for a in report_data.get('alerts', [])])}
    </table>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

report_generator = ReportGenerator()
