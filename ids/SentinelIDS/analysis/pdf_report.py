from pathlib import Path
from datetime import datetime
import json

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.colors import HexColor, white
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4


BASE = Path(__file__).resolve().parent.parent
REPORT_FOLDER = BASE / "reports"

styles = getSampleStyleSheet()

title_style = styles["Heading1"]
title_style.alignment = TA_CENTER
title_style.textColor = HexColor("#C1121F")

heading_style = styles["Heading2"]
heading_style.textColor = HexColor("#003049")

normal_style = styles["BodyText"]
def add_heading(story, text):

    story.append(Paragraph(text, heading_style))
    story.append(Spacer(1, 0.15 * inch))


def add_table(story, rows):

    table = Table(rows, colWidths=[2.2 * inch, 4.1 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#003049")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CFCFCF")),
                ("BACKGROUND", (0, 1), (-1, -1), HexColor("#F8F9FA")),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                ("TOPPADDING", (0, 1), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 0.2 * inch))


def format_timestamp(timestamp):

    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(timestamp).strftime(
            "%d %b %Y • %I:%M:%S %p"
        )

    try:
        dt = datetime.fromisoformat(str(timestamp))
        return dt.strftime("%d %b %Y • %I:%M:%S %p")
    except Exception:
        return str(timestamp)


def severity_color(level):

    colors = {
        "CRITICAL": "#8B0000",
        "HIGH": "#C1121F",
        "MEDIUM": "#F77F00",
        "LOW": "#2A9D8F",
    }

    return colors.get(str(level).upper(), "#6B7280")
def generate_pdf(report_path):

    with open(report_path, "r") as file:
        report = json.load(file)

    analysis = report.get("analysis", {})
    traffic = analysis.get("network_analysis", {})
    mitre = analysis.get("mitre_attack", {})
    nmap = analysis.get("nmap_analysis", {})
    ioc = analysis.get("indicators_of_compromise", {})

    severity = report.get("severity", "LOW")
    sev_color = severity_color(severity)

    pdf_path = report_path.with_suffix(".pdf")

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30,
    )

    story = []

    story.append(Paragraph("SENTINELIDS INCIDENT REPORT", title_style))

    story.append(
        Paragraph(
            f'<para align="center"><font color="{sev_color}" size="15"><b>{severity.upper()} RISK INCIDENT</b></font></para>',
            normal_style,
        )
    )

    story.append(
        Paragraph(
            '<para align="center"><font size="11">AI-Powered Intrusion Detection & Threat Analysis</font></para>',
            normal_style,
        )
    )

    story.append(Spacer(1, 0.25 * inch))

    cover = [
        ["Field", "Value"],
        ["Timestamp", format_timestamp(report.get("timestamp"))],
        ["Source IP", report.get("source_ip", "-")],
        ["Target IP", report.get("target_ip", "-")],
        ["Protocol", report.get("protocol", "TCP")],
        ["Severity", severity],
        ["Risk Score", str(report.get("risk_score", "-"))],
        ["Decision Action", report.get("action", "-")],
    ]

    add_table(story, cover)

    summary = analysis.get("executive_summary", "").strip()

    if summary:
        add_heading(story, "1. Executive Summary")
        story.append(Paragraph(summary, normal_style))
        story.append(Spacer(1, 0.25 * inch))

    add_heading(story, "2. Attack Overview")

    attack_table = [
        ["Field", "Value"],
        ["Attack Type", analysis.get("attack_type", "Unknown")],
        ["Severity", analysis.get("severity", severity)],
        ["Risk Score", str(analysis.get("risk_score", report.get("risk_score", "-")))],
    ]

    add_table(story, attack_table)

    # ======================================================
    # MITRE ATT&CK
    # ======================================================

    if mitre:
        add_heading(story, "3. MITRE ATT&CK Mapping")

        mitre_table = [
            ["MITRE Field", "Value"],
            ["Technique ID", mitre.get("technique_id", "")],
            ["Technique Name", mitre.get("technique_name", "")],
            ["Tactic", mitre.get("tactic", "")],
        ]

        add_table(story, mitre_table)

    # ======================================================
    # NETWORK TRAFFIC ANALYSIS
    # ======================================================

    add_heading(story, "4. Network Traffic Analysis")

    signatures = [
        item.get("signature", "")
        for item in report.get("signature_alert", [])
        if item.get("signature")
    ]

    traffic_table = [
        ["Traffic Field", "Value"],
        ["Source IP", traffic.get("source_ip", report.get("source_ip", "-"))],
        ["Target IP", traffic.get("target_ip", report.get("target_ip", "-"))],
        ["Protocol", traffic.get("protocol", report.get("protocol", "TCP"))],
        ["Detected Signatures", ", ".join(signatures) if signatures else "None"],
    ]

    add_table(story, traffic_table)

    observation = traffic.get("traffic_observation", "").strip()

    if observation:
        story.append(
            Paragraph(
                "<b>Traffic Observation</b><br/><br/>" + observation,
                normal_style,
            )
        )
        story.append(Spacer(1, 0.25 * inch))

    # ======================================================
    # NMAP ANALYSIS
    # ======================================================

    if nmap:
        add_heading(story, "5. Nmap Scan Analysis")

        services = nmap.get("services_found", [])

        if isinstance(services, list):
            services = ", ".join(services)

        nmap_table = [
            ["Scan Result", "Value"],
            ["Host Status", nmap.get("host_status", "Not Available")],
            ["Detected Services", services if services else "None"],
        ]

        add_table(story, nmap_table)

        security = nmap.get("security_observation", "").strip()

        if security:
            story.append(
                Paragraph(
                    "<b>Security Observation</b><br/><br/>" + security,
                    normal_style,
                )
            )
            story.append(Spacer(1, 0.25 * inch))

    # ======================================================
    # INDICATORS OF COMPROMISE
    # ======================================================

    add_heading(story, "6. Indicators of Compromise")

    ioc_table = [
        ["IOC Type", "Value"],
        ["Source IP", ioc.get("source_ip", report.get("source_ip", "-"))],
        ["Target IP", ioc.get("target_ip", report.get("target_ip", "-"))],
        ["Signature", ioc.get("signature", ", ".join(signatures))],
        ["Protocol", ioc.get("protocol", report.get("protocol", "TCP"))],
    ]

    add_table(story, ioc_table)
    
    impact = analysis.get("impact_analysis", "").strip()
    
        # ======================================================
    # IMPACT ANALYSIS
    # ======================================================

    if impact:
        add_heading(story, "7. Impact Analysis")
        story.append(Paragraph(impact, normal_style))
        story.append(Spacer(1, 0.25 * inch))

    # ======================================================
    # RECOMMENDED MITIGATION
    # ======================================================

    recommendations = analysis.get("recommended_actions", [])

    if recommendations:
        add_heading(story, "8. Recommended Mitigation")

        for index, recommendation in enumerate(recommendations, start=1):
            story.append(
                Paragraph(
                    f"<b>{index}.</b> {recommendation}",
                    normal_style,
                )
            )

        story.append(Spacer(1, 0.25 * inch))

    # ======================================================
    # SOC CONCLUSION
    # ======================================================

    conclusion = analysis.get("soc_conclusion", "").strip()

    if conclusion:
        add_heading(story, "9. SOC Conclusion")
        story.append(Paragraph(conclusion, normal_style))
        story.append(Spacer(1, 0.25 * inch))

    # ======================================================
    # FOOTER
    # ======================================================

    story.append(Spacer(1, 0.35 * inch))

    story.append(
        Paragraph(
            '<para align="center"><font size="9" color="#666666"><b>Generated by SentinelIDS v1.0</b><br/>AI-Powered Intrusion Detection & Threat Analysis</font></para>',
            normal_style,
        )
    )

    doc.build(story)

    print(f"PDF Report Saved : {pdf_path.name}")


# ======================================================
# GENERATE PDF FOR ALL INCIDENT JSON REPORTS
# ======================================================

if __name__ == "__main__":

    REPORT_FOLDER.mkdir(exist_ok=True)

    reports = sorted(REPORT_FOLDER.glob("incident_*.json"))

    if not reports:
        print("No incident JSON reports found.")
        exit()

    print(f"Found {len(reports)} incident reports.\n")

    created = 0
    failed = 0

    for report_file in reports:
        try:
            generate_pdf(report_file)
            created += 1

        except Exception as error:
            failed += 1
            print(f"Failed : {report_file.name}")
            print(error)

    print("\n========== PDF SUMMARY ==========")
    print("JSON reports found :", len(reports))
    print("PDFs generated     :", created)
    print("Failed             :", failed)
    print("Reports Folder     :", REPORT_FOLDER)
    print("================================")
