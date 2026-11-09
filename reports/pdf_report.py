"""PDF report generation for VulnCloud assessments."""
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
)


def _safe(value):
    return escape(str(value if value is not None else "N/A"))


def create_pdf_report(scan_result, output):
    """Write a concise assessment PDF to a file-like output object."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"],
        alignment=TA_CENTER, textColor=colors.HexColor("#17365D"),
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"],
        textColor=colors.HexColor("#17365D"), spaceBefore=12, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SmallBody", parent=styles["BodyText"],
        fontSize=8, leading=11,
    ))

    doc = SimpleDocTemplate(
        output, pagesize=A4,
        rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="VulnCloud Security Assessment Report",
        author="VulnCloud",
    )

    story = [
        Paragraph("VulnCloud Security Assessment Report", styles["ReportTitle"]),
        Paragraph("Educational security configuration assessment", styles["Italic"]),
        Spacer(1, 8),
        Paragraph("Assessment Summary", styles["SectionHeading"]),
        Paragraph(f"<b>Target:</b> {_safe(scan_result.get('target'))}", styles["BodyText"]),
        Paragraph(f"<b>Report generated (UTC):</b> {_safe(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))}", styles["BodyText"]),
        Paragraph(f"<b>HTTP status:</b> {_safe(scan_result.get('status_code'))}", styles["BodyText"]),
    ]

    score = scan_result.get("score") or {}
    story.extend([
        Paragraph("Overall Security Score", styles["SectionHeading"]),
        Paragraph(
            f"<b>{_safe(score.get('score'))}/100 — {_safe(score.get('rating'))}</b>",
            styles["Heading2"],
        ),
        Paragraph(_safe(score.get("message")), styles["BodyText"]),
        Paragraph("HTTP Security Headers", styles["SectionHeading"]),
    ])

    header_rows = [["Security Header", "Status", "Recommendation"]]
    for item in scan_result.get("headers", []):
        header_rows.append([
            Paragraph(_safe(item.get("name")), styles["SmallBody"]),
            Paragraph(_safe(item.get("status")), styles["SmallBody"]),
            Paragraph(_safe(item.get("recommendation")), styles["SmallBody"]),
        ])
    header_table = Table(header_rows, colWidths=[47 * mm, 27 * mm, 100 * mm], repeatRows=1)
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C4D1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5F8")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(header_table)

    story.append(Paragraph("TLS / SSL Certificate Analysis", styles["SectionHeading"]))
    tls = scan_result.get("tls")
    if tls is None:
        story.append(Paragraph("Not applicable: the target uses HTTP, not HTTPS.", styles["BodyText"]))
    elif tls.get("success"):
        for label, key in [
            ("Certificate verification", "verification"),
            ("TLS version", "tls_version"),
            ("Certificate issuer", "issuer"),
            ("Expiry date", "expiry_date"),
            ("Days remaining", "days_remaining"),
        ]:
            story.append(Paragraph(f"<b>{label}:</b> {_safe(tls.get(key))}", styles["BodyText"]))
    else:
        story.append(Paragraph(f"TLS analysis failed: {_safe(tls.get('error'))}", styles["BodyText"]))

    story.append(Paragraph("Automatic Security Recommendations", styles["SectionHeading"]))
    recommendations = scan_result.get("recommendations", [])
    if recommendations:
        for rec in recommendations:
            story.append(KeepTogether([
                Paragraph(f"<b>{_safe(rec.get('title'))}</b>", styles["BodyText"]),
                Paragraph(f"<b>Finding:</b> {_safe(rec.get('finding'))}", styles["BodyText"]),
                Paragraph(f"<b>Why it matters:</b> {_safe(rec.get('why'))}", styles["BodyText"]),
                Paragraph(f"<b>Suggested fix:</b> {_safe(rec.get('fix'))}", styles["BodyText"]),
                Spacer(1, 6),
            ]))
    else:
        story.append(Paragraph("No recommendations generated from the available checks.", styles["BodyText"]))

    story.extend([
        Spacer(1, 12),
        Paragraph(
            "Disclaimer: This report is an educational indicator based on the checks "
            "performed by VulnCloud. It is not a complete penetration test or a guarantee "
            "that the target is secure. Validate recommendations before applying changes.",
            styles["SmallBody"],
        ),
    ])

    doc.build(story)
