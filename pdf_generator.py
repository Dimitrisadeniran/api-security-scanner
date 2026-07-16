# pdf_generator.py — Shepherd AI v2.0
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, Image as RLImage
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from datetime import datetime
from pathlib import Path
import hashlib
import io

# ─────────────────────────────────────────────
#  Brand Assets
# ─────────────────────────────────────────────
# Logo files ship alongside this module — add both PNGs to an `assets/`
# folder next to pdf_generator.py in the repo. Everything degrades
# gracefully (falls back to text) if either file is missing, so a
# forgotten asset never breaks report generation.
BASE_DIR = Path(__file__).resolve().parent
LOGO_HEADER_PATH = BASE_DIR / "assets" / "shepherd_logo_header.png"
LOGO_WATERMARK_PATH = BASE_DIR / "assets" / "shepherd_logo_watermark.png"

# ─────────────────────────────────────────────
#  Brand Colors
# ─────────────────────────────────────────────
GREEN       = colors.HexColor("#10b981")
RED         = colors.HexColor("#ef4444")
DARK_RED    = colors.HexColor("#7f1d1d")
YELLOW      = colors.HexColor("#f59e0b")
DARK_BG     = colors.HexColor("#111827")
GRAY        = colors.HexColor("#6b7280")
LIGHT_GRAY  = colors.HexColor("#f3f4f6")
WHITE       = colors.white
BLACK       = colors.black

def get_score_color(score: float):
    if score >= 80: return GREEN
    if score >= 50: return YELLOW
    return RED

SEVERITY_COLORS = {
    "CONFIRMED_LEAK": DARK_RED,
    "CRITICAL":       RED,
    "WARNING":         YELLOW,
    "INFO":            GRAY,
}

SEVERITY_LABELS = {
    "CONFIRMED_LEAK": "CONFIRMED LEAK",
    "CRITICAL":        "Critical",
    "WARNING":          "Warning",
    "INFO":             "Low",
}

def _get_severity(finding: dict) -> str:
    """
    Reads finding['severity'] if present (v2.0 findings).
    Falls back to the old is_critical/compliance boolean logic for any
    finding shape that predates the severity field.
    """
    if finding.get("severity"):
        return finding["severity"]
    if finding.get("is_critical"):
        return "CRITICAL"
    if finding.get("compliance"):
        return "WARNING"
    return "INFO"


def _make_report_id(target_url: str, score: float, compliance_score, findings_count: int, user_email: str) -> str:
    """
    Derives a verification ID from the report's actual content rather than
    a random value. The same underlying scan always produces the same ID —
    re-downloading it later yields an identical ID, but if the numbers on
    a printed/copied report were altered, recomputing the ID from the
    (now different) content would no longer match what's printed on it.
    """
    source = f"{target_url}|{round(score, 1)}|{compliance_score}|{findings_count}|{user_email}"
    digest = hashlib.sha256(source.encode()).hexdigest()[:12].upper()
    return f"SHPD-{digest}"


def _draw_page_decoration(canvas, doc, report_id: str):
    """
    Drawn on every page: a faint logo watermark and a footer carrying
    the report ID + page number, so a page can't be separated from its
    source report and passed off as something else.
    """
    canvas.saveState()
    if LOGO_WATERMARK_PATH.exists():
        wm_w = 130 * mm
        wm_h = wm_w  # scaled per-image below via drawImage's preserveAspectRatio
        canvas.drawImage(
            str(LOGO_WATERMARK_PATH),
            (A4[0] - wm_w) / 2, (A4[1] - wm_h) / 2,
            width=wm_w, height=wm_h,
            mask="auto", preserveAspectRatio=True, anchor="c",
        )
    else:
        # Fallback if the logo asset hasn't been added to the repo yet
        canvas.setFont("Helvetica-Bold", 62)
        canvas.setFillColor(colors.Color(0.10, 0.14, 0.22, alpha=0.05))
        canvas.translate(A4[0] / 2, A4[1] / 2)
        canvas.rotate(38)
        canvas.drawCentredString(0, 0, "SHEPHERD AI")
    canvas.restoreState()

    canvas.saveState()
    canvas.setStrokeColor(LIGHT_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 14 * mm, A4[0] - 20 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(GRAY)
    canvas.drawString(20 * mm, 10 * mm, f"Report ID: {report_id}  •  Verify authenticity at shepherdai.dev/verify")
    canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()

# ─────────────────────────────────────────────
#  Main PDF Generator
# ─────────────────────────────────────────────
def generate_pdf_report(
    target_url: str,
    score: float,
    findings: list,
    user_email: str,
    tier: str,
    company_name: str = "Shepherd AI",
    compliance_score: float = None,
    audit_status_label: str = None,
    confirmed_leak_count: int = 0,
) -> bytes:
    """
    Generates a compliance PDF report (NDPA / PCI / HIPAA).
    Returns raw bytes — ready to stream to the browser.

    compliance_score / audit_status_label / confirmed_leak_count are
    optional (v2.0 fields) — the report still renders correctly without
    them, just without the compliance-readiness section.
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
    report_id = _make_report_id(target_url, score, compliance_score, len(findings), user_email)

    title_data = [[
        RLImage(str(LOGO_HEADER_PATH), width=14*mm, height=14*mm*(440/500)) if LOGO_HEADER_PATH.exists() else "",
        Paragraph(f"{company_name}", header_style),
        Paragraph(f"Compliance Risk Report — NDPA · PCI · HIPAA", sub_style),
    ]]

    title_table = Table(title_data, colWidths=[20*mm, 100*mm, 50*mm], rowHeights=18*mm)

    title_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), DARK_BG),
        ("LEFTPADDING", (0, 0), (0, -1), 8),
        ("LEFTPADDING", (1, 0), (1, -1), 4),
        ("RIGHTPADDING",(0, 0), (-1, -1), 12),
        ("TOPPADDING",  (0, 0), (-1, -1), 15),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
    ]))

    story.append(title_table)
    story.append(Spacer(1, 8*mm))

    # ── Meta Info ───────────────────────────
    story.append(Paragraph("Report Details", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Spacer(1, 3*mm))

    meta_data = [
        ["Report ID",    report_id],
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

    # ── Compliance Readiness (v2.0 — only if data was passed in) ──
    if compliance_score is not None:
        story.append(Paragraph("Compliance Readiness", section_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
        story.append(Spacer(1, 3*mm))

        compliance_color = get_score_color(compliance_score)
        compliance_style = ParagraphStyle(
            "compliance", fontSize=36, textColor=compliance_color,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        )
        status_style = ParagraphStyle(
            "status", fontSize=12, textColor=compliance_color,
            fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=6,
        )
        leak_note_style = ParagraphStyle(
            "leaknote", fontSize=10, textColor=DARK_RED,
            fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=4,
        )

        story.append(Paragraph(f"{compliance_score}/100", compliance_style))
        story.append(Paragraph(audit_status_label or "", status_style))
        if confirmed_leak_count > 0:
            plural = "s" if confirmed_leak_count != 1 else ""
            story.append(Paragraph(
                f"🔴 {confirmed_leak_count} CONFIRMED data leak{plural} found in live API responses — highest priority to fix",
                leak_note_style
            ))
        story.append(Spacer(1, 6*mm))

    # ── Score Summary ────────────────────────
    story.append(Paragraph("Security Score", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Spacer(1, 3*mm))

    score_color  = get_score_color(score)
    total_routes = len(findings)
    severities   = [_get_severity(f) for f in findings]
    confirmed    = sum(1 for s in severities if s == "CONFIRMED_LEAK")
    critical     = sum(1 for s in severities if s == "CRITICAL")
    warnings     = sum(1 for s in severities if s == "WARNING")

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

    summary_rows = [
        [Paragraph("Unprotected Routes", label_style)],
        [Paragraph(str(total_routes),     value_style)],
    ]
    if confirmed > 0:
        summary_rows += [
            [Paragraph("Confirmed Leaks", label_style)],
            [Paragraph(str(confirmed), ParagraphStyle("v2", parent=value_style, textColor=DARK_RED))],
        ]
    summary_rows += [
        [Paragraph("Critical Findings",   label_style)],
        [Paragraph(str(critical),         value_style)],
        [Paragraph("Warnings",            label_style)],
        [Paragraph(str(warnings),         value_style)],
    ]

    score_data = [[
        Paragraph(f"{score:.1f}%", score_style),
        Table(summary_rows, colWidths=[80*mm])
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
            "✅ No unprotected routes detected. All routes are secured.",
            ParagraphStyle("ok", fontSize=10, textColor=GREEN, fontName="Helvetica-Bold")
        ))
    else:
        # Sort so CONFIRMED_LEAK / CRITICAL findings surface first
        severity_order = {"CONFIRMED_LEAK": 0, "CRITICAL": 1, "WARNING": 2, "INFO": 3}
        findings_sorted = sorted(findings, key=lambda f: severity_order.get(_get_severity(f), 4))

        table_data = [[
            Paragraph("Route",       ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Method",      ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Risk",        ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Frameworks",  ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Evidence",    ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
        ]]

        row_styles = []
        for i, f in enumerate(findings_sorted, start=1):
            severity    = _get_severity(f)
            risk_color  = SEVERITY_COLORS.get(severity, GRAY)
            risk_label  = SEVERITY_LABELS.get(severity, "Low")
            frameworks  = ", ".join(f.get("compliance", [])) or "—"

            # Evidence column: prefer real confirmed-leak evidence (redacted),
            # fall back to schema-based PII pattern names.
            leak_evidence = f.get("leak_evidence") or []
            if leak_evidence:
                evidence_text = ", ".join(
                    f"{e.get('type', '?')}: {e.get('preview', '')}" for e in leak_evidence
                )
            else:
                evidence_text = ", ".join(f.get("pii_detected", [])) or "—"

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
            evidence_para = Paragraph(
                evidence_text,
                ParagraphStyle("cell", fontSize=8, fontName="Helvetica", textColor=BLACK)
            )

            table_data.append([route_para, method_para, risk_para, fw_para, evidence_para])

            bg = LIGHT_GRAY if i % 2 == 0 else WHITE
            row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

        findings_table = Table(
            table_data,
            colWidths=[50*mm, 16*mm, 22*mm, 32*mm, 50*mm]
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
        f"This report was generated automatically by Shepherd AI on {now} and carries verification ID "
        f"<b>{report_id}</b>, derived from this report's own data. Confirmed-leak evidence shown above is "
        f"redacted — Shepherd AI never stores the full value of any sensitive data it detects. "
        f"This report is intended for compliance review purposes only and does not constitute legal advice.",
        small_style
    ))

    decorate = lambda c, d: _draw_page_decoration(c, d, report_id)
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    buffer.seek(0)
    return buffer.read()
