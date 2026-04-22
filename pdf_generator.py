# pdf_generator.py
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from datetime import datetime
import io

# ─────────────────────────────────────────────
#  Brand Colors
# ─────────────────────────────────────────────
GREEN      = colors.HexColor("#10b981")
RED        = colors.HexColor("#ef4444")
YELLOW     = colors.HexColor("#f59e0b")
DARK_BG    = colors.HexColor("#111827")
GRAY       = colors.HexColor("#6b7280")
LIGHT_GRAY = colors.HexColor("#f3f4f6")
WHITE      = colors.white
BLACK      = colors.black

def get_score_color(score: float):
    if score >= 80: return GREEN
    if score >= 50: return YELLOW
    return RED

def get_risk_color(is_critical: bool, compliance: list):
    if is_critical: return RED
    if compliance:  return YELLOW
    return GREEN

# ─────────────────────────────────────────────
#  Main PDF Generator
# ─────────────────────────────────────────────
def generate_pdf_report(
    target_url: str,
    score: float,
    findings: list,
    user_email: str,
    tier: str,
    company_name: str = "Shepherd AI"
) -> bytes:
    """
    Generates a HIPAA compliance PDF report.
    Returns raw bytes — ready to stream to the browser.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Header ──────────────────────────────
    header_style = ParagraphStyle(
        "header",
        fontSize=22,
        textColor=WHITE,
        fontName="Helvetica-Bold",
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        "sub",
        fontSize=10,
        textColor=GRAY,
        fontName="Helvetica",
        alignment=TA_LEFT,
        spaceAfter=2,
    )
    label_style = ParagraphStyle(
        "label",
        fontSize=9,
        textColor=GRAY,
        fontName="Helvetica",
        spaceAfter=2,
    )
    value_style = ParagraphStyle(
        "value",
        fontSize=11,
        textColor=BLACK,
        fontName="Helvetica-Bold",
        spaceAfter=8,
    )
    section_style = ParagraphStyle(
        "section",
        fontSize=13,
        textColor=BLACK,
        fontName="Helvetica-Bold",
        spaceBefore=12,
        spaceAfter=6,
    )
    small_style = ParagraphStyle(
        "small",
        fontSize=9,
        textColor=GRAY,
        fontName="Helvetica",
        spaceAfter=4,
    )

    # ── Title Block ──────────────────────────
    now = datetime.now().strftime("%B %d, %Y at %H:%M UTC")

    title_data = [[
        Paragraph(f"{company_name}", header_style),
        Paragraph(f"HIPAA Compliance Report", sub_style),
    ]]
    title_table = Table(title_data, colWidths=[120*mm, 50*mm])
    title_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), DARK_BG),
        ("PADDING",     (0, 0), (-1, -1), 12),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(title_table)
    story.append(Spacer(1, 8*mm))

    # ── Meta Info ───────────────────────────
    story.append(Paragraph("Report Details", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Spacer(1, 3*mm))

    meta_data = [
        ["Generated",    now],
        ["Target API",   target_url],
        ["Prepared for", user_email],
        ["Plan",         tier.upper()],
    ]
    meta_table = Table(meta_data, colWidths=[40*mm, 130*mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",   (0, 0), (0, -1), GRAY),
        ("TEXTCOLOR",   (1, 0), (1, -1), BLACK),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6*mm))

    # ── Score Summary ────────────────────────
    story.append(Paragraph("Security Score", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Spacer(1, 3*mm))

    score_color  = get_score_color(score)
    total_routes = len(findings)
    critical     = sum(1 for f in findings if f.get("is_critical"))
    warnings     = sum(1 for f in findings if not f.get("is_critical") and f.get("compliance"))

    score_style = ParagraphStyle(
        "score",
        fontSize=48,
        textColor=score_color,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    verdict = (
        "✅ Healthy — All critical routes are secured."     if score >= 80 else
        "⚠️  At Risk — Some PHI routes need protection."   if score >= 50 else
        "🚨 Critical — Immediate action required."
    )
    verdict_style = ParagraphStyle(
        "verdict",
        fontSize=11,
        textColor=score_color,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=6,
    )

    score_data = [[
        Paragraph(f"{score:.1f}%", score_style),
        Table([
            [Paragraph("Unprotected Routes", label_style)],
            [Paragraph(str(total_routes),     value_style)],
            [Paragraph("Critical Findings",   label_style)],
            [Paragraph(str(critical),         value_style)],
            [Paragraph("Warnings",            label_style)],
            [Paragraph(str(warnings),         value_style)],
        ], colWidths=[80*mm])
    ]]
    score_table = Table(score_data, colWidths=[80*mm, 90*mm])
    score_table.setStyle(TableStyle([
        ("VALIGN",   (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING",  (0, 0), (-1, -1), 8),
        ("BOX",      (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(verdict, verdict_style))
    story.append(Spacer(1, 6*mm))

    # ── Findings Table ───────────────────────
    story.append(Paragraph("Detailed Findings", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Spacer(1, 3*mm))

    if not findings:
        story.append(Paragraph(
            "✅ No unprotected PHI routes detected. All routes are secured.",
            ParagraphStyle("ok", fontSize=10, textColor=GREEN, fontName="Helvetica-Bold")
        ))
    else:
        # Table header
        table_data = [[
            Paragraph("Route",       ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Method",      ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Risk",        ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Frameworks",  ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("PII Detected",ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
        ]]

        row_styles = []
        for i, f in enumerate(findings, start=1):
            risk_color  = get_risk_color(f.get("is_critical", False), f.get("compliance", []))
            risk_label  = "Critical" if f.get("is_critical") else "Warning" if f.get("compliance") else "Low"
            frameworks  = ", ".join(f.get("compliance", [])) or "—"
            pii         = ", ".join(f.get("pii_detected", [])) or "—"

            route_para = Paragraph(
                f.get("route", ""),
                ParagraphStyle("cell", fontSize=8, fontName="Helvetica", textColor=BLACK)
            )
            method_para = Paragraph(
                f.get("method", ""),
                ParagraphStyle("cell", fontSize=8, fontName="Helvetica-Bold", textColor=BLACK)
            )
            risk_para = Paragraph(
                risk_label,
                ParagraphStyle("risk", fontSize=8, fontName="Helvetica-Bold", textColor=risk_color)
            )
            fw_para = Paragraph(
                frameworks,
                ParagraphStyle("cell", fontSize=8, fontName="Helvetica", textColor=BLACK)
            )
            pii_para = Paragraph(
                pii,
                ParagraphStyle("cell", fontSize=8, fontName="Helvetica", textColor=BLACK)
            )

            table_data.append([route_para, method_para, risk_para, fw_para, pii_para])

            # Alternate row colors
            bg = LIGHT_GRAY if i % 2 == 0 else WHITE
            row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

        findings_table = Table(
            table_data,
            colWidths=[55*mm, 18*mm, 18*mm, 35*mm, 44*mm]
        )
        findings_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), DARK_BG),
            ("PADDING",     (0, 0), (-1, -1), 6),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("GRID",        (0, 0), (-1, -1), 0.25, LIGHT_GRAY),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            *row_styles,
        ]))
        story.append(findings_table)

    story.append(Spacer(1, 8*mm))

    # ── Footer ───────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        f"This report was generated automatically by Shepherd AI on {now}. "
        f"It is intended for compliance review purposes only. "
        f"Shepherd AI does not provide legal advice.",
        small_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()