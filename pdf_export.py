"""
Export scan report as PDF using ReportLab.
"""
from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


def build_pdf(devices: list[dict[str, Any]], cidr: str | None = None) -> bytes:
    """Build PDF report buffer from device list. Returns PDF bytes."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=inch,
        bottomMargin=inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name="CustomTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
        alignment=TA_CENTER,
    )
    story = []
    story.append(Paragraph("NetScope – Network Scan Report", title_style))
    story.append(Spacer(1, 12))
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    network = cidr or "Local network"
    story.append(Paragraph(f"Scan time: {ts}", styles["Normal"]))
    story.append(Paragraph(f"Network: {network}", styles["Normal"]))
    story.append(Paragraph(f"Devices found: {len(devices)}", styles["Normal"]))
    story.append(Spacer(1, 24))

    # Device table
    headers = ["IP", "MAC", "Vendor", "Device name", "Risk", "Open ports", "Packets (↑/↓)"]
    rows = [[
        d.get("ip", ""),
        d.get("mac", ""),
        (d.get("vendor") or "-"),
        (d.get("device_name") or "-"),
        (d.get("risk") or "low").upper(),
        ", ".join(map(str, d.get("open_ports") or [])) or "-",
        f"{d.get('packets_sent', 0)} / {d.get('packets_received', 0)}",
    ] for d in devices]
    table_data = [headers] + rows
    t = Table(table_data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
    ]))
    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
