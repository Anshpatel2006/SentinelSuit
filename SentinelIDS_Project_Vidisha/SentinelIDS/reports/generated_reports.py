
from pathlib import Path
import json

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch

BASE = Path(__file__).resolve().parent.parent

AI_FILE = BASE / "data" / "ai_reports.jsonl"
OUTPUT_FILE = BASE / "reports" / "SentinelIDS_SOC_Report.pdf"

styles = getSampleStyleSheet()

TITLE = styles["Heading1"]
TITLE.alignment = TA_CENTER
TITLE.textColor = colors.HexColor("#003366")

H1 = styles["Heading2"]
H1.textColor = colors.HexColor("#0F4C81")

BODY = styles["BodyText"]
BODY.leading = 18


def footer(canvas, doc):
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.grey)
    canvas.drawString(35, 20, "SentinelIDS | AI Security Operations Center")
    canvas.drawRightString(560, 20, f"Page {doc.page}")


def severity_badge(level):
    level = level.upper()

    if level == "HIGH":
        bg = colors.red
    elif level == "MEDIUM":
        bg = colors.orange
    else:
        bg = colors.green

    table = Table([[level]], colWidths=[2 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("TEXTCOLOR", (0,0), (-1,-1), colors.white),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold")
    ]))

    return table


def build_report():

    if not AI_FILE.exists():
        print("ai_reports.jsonl not found.")
        return

    with open(AI_FILE, "r") as f:
        report = json.load(f)

    ai = report["analysis"]

    doc = SimpleDocTemplate(
        str(OUTPUT_FILE),
        leftMargin=35,
        rightMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    story = []

    # COVER
    story.append(Paragraph("SENTINELIDS INCIDENT REPORT", TITLE))
    story.append(Paragraph("AI-Powered Intrusion Detection & Threat Analysis", styles["Title"]))
    story.append(Spacer(1, 0.3 * inch))

    story.append(severity_badge(ai["severity"]))
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("<b>Executive Summary</b>", H1))
    story.append(Paragraph(ai["incident_summary"], BODY))
    story.append(PageBreak())

    # INCIDENT DETAILS
    story.append(Paragraph("Incident Details", H1))

    details = [
        ["Field", "Value"],
        ["Incident Time", report["timestamp"]],
        ["Source IP", report["source_ip"]],
        ["Target IP", report["target_ip"]],
        ["Detection Signature", report["signature"]],
        ["Severity", ai["severity"]],
        ["Risk Score", str(ai["risk_score"]) + "/100"],
        ["Attack Type", ai["attack_type"]]
    ]

    table = Table(details, colWidths=[2.2 * inch, 4 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#003366")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("BACKGROUND", (0,1), (0,-1), colors.HexColor("#EAF2FF")),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8)
    ]))

    story.append(table)
    story.append(Spacer(1, 0.25 * inch))

    # LIVE TRAFFIC
    story.append(Paragraph("Live Traffic Analysis", H1))

    traffic = ai["traffic_analysis"]

    traffic_table = [
        ["Feature", "Observed Value"],
        ["Protocol", traffic["protocol"]],
        ["Source IP", traffic["source_ip"]],
        ["Target IP", traffic["target_ip"]],
        ["Destination Port", traffic["destination_port"]],
        ["Flow Duration", traffic["flow_duration"]],
        ["Flow Packets / Second", traffic["flow_packets_per_sec"]],
        ["Flow Bytes / Second", traffic["flow_bytes_per_sec"]],
        ["SYN Flag Count", traffic["syn_flag_count"]],
        ["ACK Flag Count", traffic["ack_flag_count"]],
        ["RST Flag Count", traffic["rst_flag_count"]]
    ]

    table = Table(traffic_table, colWidths=[2.8 * inch, 3.4 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0F4C81")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,1), (-1,-1), colors.whitesmoke),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8)
    ]))

    story.append(table)
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("<b>Traffic Observation</b>", BODY))
    story.append(Paragraph(traffic["packet_observation"], BODY))
    story.append(PageBreak())

    # MITRE + IOC
    story.append(Paragraph("Threat Intelligence Analysis", H1))

    mitre = ai["mitre_attack"]

    mitre_table = [
        ["MITRE ATT&CK Field", "Value"],
        ["Technique ID", mitre["technique_id"]],
        ["Technique Name", mitre["technique_name"]],
        ["Tactic", mitre["tactic"]]
    ]

    table = Table(mitre_table, colWidths=[2.5 * inch, 3.6 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#003366")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#EAF2FF"))
    ]))

    story.append(table)
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("Indicators of Compromise (IOC)", H1))

    ioc = ai["indicators_of_compromise"]

    ioc_table = [
        ["Indicator", "Observed Value"],
        ["Source IP", ioc["source_ip"]],
        ["Target IP", ioc["target_ip"]],
        ["Destination Port", ioc["destination_port"]],
        ["Protocol", ioc["protocol"]],
        ["Detection Signature", ioc["signature"]]
    ]

    table = Table(ioc_table, colWidths=[2.5 * inch, 3.6 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0F4C81")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,1), (-1,-1), colors.whitesmoke)
    ]))

    story.append(table)
    story.append(Spacer(1, 0.3 * inch))

    # NMAP
    story.append(Paragraph("Network Scan Analysis (Nmap)", H1))

    nmap = ai["nmap_analysis"]

    story.append(Paragraph(f"<b>Host Status:</b> {nmap['host_status']}", BODY))
    story.append(Spacer(1, 0.1 * inch))

    services = [["Port", "State", "Service"]]

    for service in nmap["services_found"]:
        services.append([
            str(service["port"]),
            service["state"],
            service["service"]
        ])

    table = Table(services, colWidths=[1 * inch, 1.5 * inch, 3.5 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#003366")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#F8FAFF"))
    ]))

    story.append(table)
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("<b>Security Observation</b>", BODY))
    story.append(Paragraph(nmap["security_observation"], BODY))
    story.append(PageBreak())

    # IMPACT
    story.append(Paragraph("Impact Assessment", H1))
    story.append(Paragraph(ai["impact_analysis"], BODY))
    story.append(Spacer(1, 0.3 * inch))

    # RECOMMENDATIONS
    story.append(Paragraph("Security Recommendations", H1))

    recommendations = [["Priority", "Recommendation"]]

    priority = ["HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"]

    for i, rec in enumerate(ai["recommendations"]):
        recommendations.append([priority[i], rec])

    table = Table(recommendations, colWidths=[1.2 * inch, 4.9 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#003366")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#EDF4FF"))
    ]))

    story.append(table)
    story.append(Spacer(1, 0.3 * inch))

    # CONCLUSION
    story.append(Paragraph("SOC Analyst Conclusion", H1))
    story.append(Paragraph(ai["soc_conclusion"], BODY))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)

    print("=" * 55)
    print("SentinelIDS SOC Report Generated Successfully")
    print("Saved :", OUTPUT_FILE)
    print("=" * 55)


if __name__ == "__main__":
    build_report()
