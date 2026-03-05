"""
pdf_generator.py
────────────────────────────────────────────────────────────────────────────────
Enterprise PDF Reporting Engine — APK Security Analysis

Consumes a MappedReport dict (from vulnerability_mapper.generate_report) and
produces a polished, multi-section PDF audit report styled after professional
cybersecurity deliverables.

Report structure
─────────────────
  Cover page      — title, package name, scan date, classification band
  ToC             — auto-generated section list
  Executive Summary — severity pie chart + key metrics table
  Findings         — one section per vulnerability with evidence table
  Appendix         — full permission inventory

Entry point
─────────────────
    from pdf_generator import generate_pdf_report
    pdf_bytes: bytes = generate_pdf_report(mapped_report_dict)

Dependencies
─────────────────
    pip install reportlab matplotlib
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import io
import logging
import re
import textwrap
from datetime import datetime, timezone
from typing import Any

import matplotlib
matplotlib.use("Agg")  # headless backend — no display required
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.figure import Figure

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm, cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Colour palette  (dark navy / amber brand — professional cyber aesthetic)
# ──────────────────────────────────────────────────────────────────────────────

class C:
    """Central colour constants used throughout the report."""
    NAVY_DARK   = colors.HexColor("#0a0f1e")
    NAVY_MED    = colors.HexColor("#0f1a35")
    NAVY_LIGHT  = colors.HexColor("#1a2a4a")
    ACCENT      = colors.HexColor("#1e5fa8")        # brand blue
    ACCENT_PALE = colors.HexColor("#ddeeff")
    WHITE       = colors.white
    NEAR_WHITE  = colors.HexColor("#f4f6fb")
    LIGHT_GREY  = colors.HexColor("#e8ecf4")
    MID_GREY    = colors.HexColor("#8a95aa")
    DARK_TEXT   = colors.HexColor("#111827")
    BODY_TEXT   = colors.HexColor("#374151")

    # Severity colours (must align with charts and badge CSS in the frontend)
    CRITICAL    = colors.HexColor("#dc2626")
    HIGH        = colors.HexColor("#ea580c")
    MEDIUM      = colors.HexColor("#ca8a04")
    LOW         = colors.HexColor("#2563eb")
    INFO        = colors.HexColor("#6b7280")

    # Table chrome
    TABLE_HEADER = colors.HexColor("#1a2a4a")
    TABLE_ALT    = colors.HexColor("#f0f4fb")
    TABLE_BORDER = colors.HexColor("#c8d4e8")


SEV_COLORS: dict[str, Any] = {
    "CRITICAL": C.CRITICAL,
    "HIGH":     C.HIGH,
    "MEDIUM":   C.MEDIUM,
    "LOW":      C.LOW,
    "INFO":     C.INFO,
}

# Matplotlib hex strings for the pie chart
SEV_HEX: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}


# ──────────────────────────────────────────────────────────────────────────────
# Typography
# ──────────────────────────────────────────────────────────────────────────────

def _build_styles() -> dict[str, ParagraphStyle]:
    """Return all named ParagraphStyles used by the report."""
    base = getSampleStyleSheet()

    def S(name: str, **kw) -> ParagraphStyle:
        """Shorthand: derive from 'Normal' with overrides."""
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        # Cover page
        "cover_eyebrow":  S("cover_eyebrow",
            fontName="Helvetica", fontSize=9, textColor=C.ACCENT_PALE,
            leading=14, spaceAfter=6, alignment=TA_CENTER, tracking=2),
        "cover_title":    S("cover_title",
            fontName="Helvetica-Bold", fontSize=28, textColor=C.WHITE,
            leading=36, spaceAfter=8, alignment=TA_CENTER),
        "cover_subtitle": S("cover_subtitle",
            fontName="Helvetica", fontSize=13, textColor=C.ACCENT_PALE,
            leading=20, spaceAfter=4, alignment=TA_CENTER),
        "cover_meta":     S("cover_meta",
            fontName="Helvetica", fontSize=9, textColor=C.MID_GREY,
            leading=14, alignment=TA_CENTER),

        # Body headings
        "h1": S("h1",
            fontName="Helvetica-Bold", fontSize=16, textColor=C.NAVY_DARK,
            leading=22, spaceBefore=14, spaceAfter=6),
        "h2": S("h2",
            fontName="Helvetica-Bold", fontSize=12, textColor=C.ACCENT,
            leading=18, spaceBefore=10, spaceAfter=4),
        "h3": S("h3",
            fontName="Helvetica-BoldOblique", fontSize=10, textColor=C.NAVY_DARK,
            leading=15, spaceBefore=8, spaceAfter=3),

        # Severity inline headings (used in vuln section headers)
        "sev_critical": S("sev_critical",
            fontName="Helvetica-Bold", fontSize=10, textColor=C.CRITICAL, leading=15),
        "sev_high":     S("sev_high",
            fontName="Helvetica-Bold", fontSize=10, textColor=C.HIGH, leading=15),
        "sev_medium":   S("sev_medium",
            fontName="Helvetica-Bold", fontSize=10, textColor=C.MEDIUM, leading=15),
        "sev_low":      S("sev_low",
            fontName="Helvetica-Bold", fontSize=10, textColor=C.LOW, leading=15),
        "sev_info":     S("sev_info",
            fontName="Helvetica-Bold", fontSize=10, textColor=C.INFO, leading=15),

        # Body text
        "body": S("body",
            fontName="Helvetica", fontSize=9.5, textColor=C.BODY_TEXT,
            leading=15, spaceAfter=5, alignment=TA_JUSTIFY),
        "body_small": S("body_small",
            fontName="Helvetica", fontSize=8.5, textColor=C.BODY_TEXT,
            leading=13, spaceAfter=3),
        "label": S("label",
            fontName="Helvetica-Bold", fontSize=8.5, textColor=C.NAVY_DARK,
            leading=13, spaceAfter=2),
        "mono": S("mono",
            fontName="Courier", fontSize=8, textColor=C.BODY_TEXT,
            leading=12, spaceAfter=2),
        "toc_entry": S("toc_entry",
            fontName="Helvetica", fontSize=9.5, textColor=C.BODY_TEXT,
            leading=16, leftIndent=6),
        "footer": S("footer",
            fontName="Helvetica", fontSize=7.5, textColor=C.MID_GREY,
            leading=10, alignment=TA_CENTER),
        "caption": S("caption",
            fontName="Helvetica-Oblique", fontSize=8, textColor=C.MID_GREY,
            leading=12, alignment=TA_CENTER, spaceAfter=4),

        # Metric tile
        "metric_number": S("metric_number",
            fontName="Helvetica-Bold", fontSize=26, textColor=C.NAVY_DARK,
            leading=30, alignment=TA_CENTER),
        "metric_label": S("metric_label",
            fontName="Helvetica", fontSize=8, textColor=C.MID_GREY,
            leading=12, alignment=TA_CENTER),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Page templates
# ──────────────────────────────────────────────────────────────────────────────

W, H = A4          # 595.3 × 841.9 pt
MARGIN_LR = 20*mm
MARGIN_TOP = 22*mm
MARGIN_BOT = 22*mm
CONTENT_W  = W - 2 * MARGIN_LR


def _cover_page_cb(canvas, doc):
    """Paint the cover page background and decorative elements."""
    canvas.saveState()

    # Full-bleed dark background
    canvas.setFillColor(C.NAVY_DARK)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)

    # Vertical accent stripe — left
    canvas.setFillColor(C.ACCENT)
    canvas.rect(0, 0, 4, H, fill=1, stroke=0)

    # Top gradient band (faked with layered rectangles)
    for i, alpha in enumerate([0.12, 0.08, 0.05, 0.03]):
        h_band = (4 - i) * 18
        canvas.setFillColor(colors.HexColor("#1e5fa8"))
        canvas.setFillAlpha(alpha)
        canvas.rect(0, H - h_band, W, h_band, fill=1, stroke=0)

    # Horizontal rule under title zone
    canvas.setFillAlpha(1)
    canvas.setStrokeColor(C.ACCENT)
    canvas.setLineWidth(1.2)
    canvas.line(MARGIN_LR, H * 0.42, W - MARGIN_LR, H * 0.42)

    # Bottom classification band
    canvas.setFillColor(C.ACCENT)
    canvas.rect(0, 0, W, 12*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C.WHITE)
    canvas.drawCentredString(W / 2, 4.5*mm, "CONFIDENTIAL — FOR AUTHORISED RECIPIENTS ONLY")

    canvas.restoreState()


def _body_page_cb(canvas, doc):
    """Header / footer chrome for every body page."""
    canvas.saveState()
    pn = doc.page

    # Top rule
    canvas.setStrokeColor(C.ACCENT)
    canvas.setLineWidth(0.8)
    canvas.line(MARGIN_LR, H - 14*mm, W - MARGIN_LR, H - 14*mm)

    # Header left: report title
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(C.MID_GREY)
    canvas.drawString(MARGIN_LR, H - 11*mm, "Static Security Analysis Report")

    # Header right: package name (truncated)
    pkg = getattr(doc, "_pkg_name", "")
    if pkg:
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(W - MARGIN_LR, H - 11*mm, pkg[:60])

    # Bottom rule
    canvas.line(MARGIN_LR, 14*mm, W - MARGIN_LR, 14*mm)

    # Footer: page number centred
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C.MID_GREY)
    canvas.drawCentredString(W / 2, 8*mm, f"Page {pn}")

    # Footer right: date
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(
        W - MARGIN_LR, 8*mm,
        getattr(doc, "_scan_date", ""),
    )

    canvas.restoreState()


def _make_doc(buffer: io.BytesIO, pkg_name: str, scan_date: str) -> BaseDocTemplate:
    """Create the BaseDocTemplate with cover + body page templates."""
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN_LR,
        rightMargin=MARGIN_LR,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOT,
        title="Static Security Analysis Report",
        author="APK·SCAN",
        subject=pkg_name,
    )
    doc._pkg_name  = pkg_name   # injected for header cb
    doc._scan_date = scan_date

    # Cover page — full bleed, no frame margins
    cover_frame = Frame(0, 0, W, H, leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0, id="cover")
    cover_tpl   = PageTemplate(id="cover", frames=[cover_frame],
                               onPage=_cover_page_cb)

    # Body pages
    body_frame  = Frame(MARGIN_LR, MARGIN_BOT, CONTENT_W, H - MARGIN_TOP - MARGIN_BOT,
                        id="body", leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0)
    body_tpl    = PageTemplate(id="body", frames=[body_frame],
                               onPage=_body_page_cb)

    doc.addPageTemplates([cover_tpl, body_tpl])
    return doc


# ──────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ──────────────────────────────────────────────────────────────────────────────

def _safe_str(value: Any, maxlen: int = 0) -> str:
    """Convert value to string, stripping control characters."""
    s = str(value) if value is not None else ""
    # Remove non-printable except newlines/tabs
    s = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]", "", s)
    if maxlen and len(s) > maxlen:
        s = s[:maxlen - 1] + "…"
    return s


def _wrap(text: str, width: int = 80) -> str:
    """Wrap long strings for PDF cells."""
    return "\n".join(textwrap.wrap(_safe_str(text), width)) or "—"


def _sev_style(sev: str, styles: dict) -> ParagraphStyle:
    return styles.get(f"sev_{sev.lower()}", styles["sev_info"])


def _hr(thickness: float = 0.5, color: Any = C.LIGHT_GREY) -> HRFlowable:
    return HRFlowable(width="100%", thickness=thickness, color=color,
                      spaceAfter=4, spaceBefore=4)


def _vspace(pts: float) -> Spacer:
    return Spacer(1, pts)


# ──────────────────────────────────────────────────────────────────────────────
# Chart generation
# ──────────────────────────────────────────────────────────────────────────────

def _severity_pie_chart(by_severity: dict[str, int]) -> io.BytesIO:
    """
    Render a doughnut-style severity breakdown chart.

    Returns a PNG byte buffer at 150 DPI suitable for embedding in the PDF.
    The figure uses a transparent background and is sized for a half-page column.
    """
    order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    labels = []
    values = []
    hex_colours = []

    for sev in order:
        count = by_severity.get(sev, 0)
        if count > 0:
            labels.append(f"{sev}  {count}")
            values.append(count)
            hex_colours.append(SEV_HEX[sev])

    if not values:
        # Placeholder if no findings at all
        values   = [1]
        labels   = ["No Findings"]
        hex_colours = ["#e8ecf4"]

    fig, ax = plt.subplots(figsize=(4.8, 3.8), facecolor="none")

    wedges, texts, autotexts = ax.pie(
        values,
        labels=None,
        colors=hex_colours,
        autopct=lambda p: f"{p:.0f}%" if p > 4 else "",
        pctdistance=0.78,
        startangle=140,
        wedgeprops={"linewidth": 1.5, "edgecolor": "white",
                    "width": 0.52},          # doughnut: width < 1.0
        textprops={"fontsize": 9, "color": "#374151"},
    )

    for at in autotexts:
        at.set_fontsize(8.5)
        at.set_fontweight("bold")
        at.set_color("white")

    # Centre annotation: total count
    total = sum(values)
    ax.text(0, 0.08, str(total), ha="center", va="center",
            fontsize=22, fontweight="bold", color="#111827")
    ax.text(0, -0.22, "findings", ha="center", va="center",
            fontsize=8, color="#8a95aa")

    # Legend on the right
    legend_patches = [
        mpatches.Patch(facecolor=c, label=l, edgecolor="white", linewidth=0.5)
        for c, l in zip(hex_colours, labels)
    ]
    ax.legend(
        handles=legend_patches,
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        fontsize=8.5,
        frameon=False,
        labelcolor="#374151",
    )

    ax.set_aspect("equal")
    plt.tight_layout(pad=0.3)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


def _severity_bar_chart(by_severity: dict[str, int]) -> io.BytesIO:
    """
    Horizontal bar chart of finding counts — more legible than a pie at small sizes.
    Used alongside the pie in the executive summary.
    """
    order      = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    labels_raw = [s for s in order if by_severity.get(s, 0) > 0]
    values     = [by_severity[s] for s in labels_raw]
    bar_colors = [SEV_HEX[s] for s in labels_raw]

    if not values:
        labels_raw = ["No Findings"]
        values     = [0]
        bar_colors = ["#e8ecf4"]

    fig, ax = plt.subplots(figsize=(3.6, max(1.4, len(values) * 0.55 + 0.5)),
                           facecolor="none")

    bars = ax.barh(labels_raw[::-1], values[::-1], color=bar_colors[::-1],
                   height=0.55, edgecolor="none")

    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", ha="left", fontsize=9,
                fontweight="bold", color="#111827")

    ax.set_xlim(0, max(values) * 1.35 if max(values) > 0 else 1)
    ax.set_xlabel("Count", fontsize=8, color="#8a95aa")
    ax.tick_params(axis="y", labelsize=8.5, colors="#374151")
    ax.tick_params(axis="x", labelsize=7.5, colors="#8a95aa")
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color("#e8ecf4")
    ax.xaxis.set_ticks_position("bottom")
    ax.grid(axis="x", color="#e8ecf4", linewidth=0.6, linestyle="--")

    plt.tight_layout(pad=0.4)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


# ──────────────────────────────────────────────────────────────────────────────
# Section builders
# ──────────────────────────────────────────────────────────────────────────────

def _build_cover(story: list, styles: dict, pkg_name: str, scan_date: str,
                 summary: dict) -> None:
    """Append all cover-page flowables to *story*."""
    total  = summary.get("total_vulnerabilities", 0)
    by_sev = summary.get("by_severity", {})
    crits  = by_sev.get("CRITICAL", 0)

    # Push content down to vertical centre of the dark page
    story.append(_vspace(H * 0.20))

    story.append(Paragraph("CONFIDENTIAL AUDIT REPORT", styles["cover_eyebrow"]))
    story.append(_vspace(6))

    story.append(Paragraph("Static Security<br/>Analysis Report",
                            styles["cover_title"]))
    story.append(_vspace(10))

    story.append(Paragraph(_safe_str(pkg_name, 80), styles["cover_subtitle"]))
    story.append(_vspace(28))

    story.append(Paragraph(f"Scan Date: {scan_date}", styles["cover_meta"]))
    story.append(_vspace(4))
    story.append(Paragraph(
        f"Total Findings: {total}  &nbsp;·&nbsp;  "
        f"Critical: {crits}  &nbsp;·&nbsp;  "
        f"Produced by APK·SCAN",
        styles["cover_meta"],
    ))

    # Force page break immediately after the cover flowables
    story.append(NextPageTemplate("body"))
    story.append(PageBreak())


def _build_toc(story: list, styles: dict, vulns: list) -> None:
    """Lightweight manual table of contents."""
    story.append(Paragraph("Contents", styles["h1"]))
    story.append(_hr(1.2, C.ACCENT))
    story.append(_vspace(6))

    sections = [
        ("1", "Executive Summary"),
        ("2", "Vulnerability Findings"),
    ]
    for idx, vuln in enumerate(vulns, start=1):
        sev   = vuln.get("severity", "INFO")
        title = _safe_str(vuln.get("title", "—"), 70)
        sections.append((f"  2.{idx}", f"{title}  [{sev}]"))

    sections.append(("3", "Permission Inventory"))

    for num, label in sections:
        indent = 10 if num.strip().startswith("2.") else 0
        p_style = ParagraphStyle(
            "toc_inner",
            parent=styles["toc_entry"],
            leftIndent=indent,
            fontName="Helvetica-Bold" if not num.strip().startswith("2.") else "Helvetica",
            textColor=C.NAVY_DARK if not num.strip().startswith("2.") else C.BODY_TEXT,
        )
        story.append(Paragraph(f"{num}&nbsp;&nbsp;&nbsp;{label}", p_style))

    story.append(PageBreak())


def _build_executive_summary(story: list, styles: dict, app_profile: dict,
                              summary: dict) -> None:
    """Executive Summary section with metrics tiles, pie chart, and bar chart."""
    story.append(Paragraph("1  Executive Summary", styles["h1"]))
    story.append(_hr(1.2, C.ACCENT))
    story.append(_vspace(8))

    # ── Application metadata table ────────────────────────────────────────────
    sig      = app_profile.get("signature_info", {}) or {}
    pkg      = _safe_str(app_profile.get("package_name", "—"), 70)
    sdk_tgt  = _safe_str(app_profile.get("target_sdk", "—"))
    sdk_min  = _safe_str(app_profile.get("min_sdk", "—"))
    cert_cn  = _safe_str(sig.get("subject_cn", "—"))
    cert_org = _safe_str(sig.get("subject_o", "—"))
    sha256   = _safe_str(sig.get("sha256_fingerprint", "—"), 50)
    debug    = sig.get("is_debug_cert", False)

    meta_data = [
        ["Package",              pkg],
        ["Target SDK / Min SDK", f"{sdk_tgt} / {sdk_min}"],
        ["Certificate CN",       cert_cn],
        ["Certificate Org",      cert_org],
        ["SHA-256 Fingerprint",  sha256],
        ["Debug Certificate",    "YES — Release signing required" if debug else "No"],
    ]
    meta_table = Table(
        meta_data,
        colWidths=[42*mm, CONTENT_W - 42*mm],
        hAlign="LEFT",
    )
    meta_style = TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), C.TABLE_ALT),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",     (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR",    (0, 0), (-1, -1), C.BODY_TEXT),
        ("TEXTCOLOR",    (1, 5), (1, 5),
         C.CRITICAL if debug else C.LOW),         # highlight debug cert
        ("FONTNAME",     (1, 5), (1, 5),
         "Helvetica-Bold" if debug else "Helvetica"),
        ("GRID",         (0, 0), (-1, -1), 0.4, C.TABLE_BORDER),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C.WHITE, C.TABLE_ALT]),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ])
    meta_table.setStyle(meta_style)
    story.append(meta_table)
    story.append(_vspace(14))

    # ── Severity metrics tiles ────────────────────────────────────────────────
    by_sev = summary.get("by_severity", {})
    total  = summary.get("total_vulnerabilities", 0)

    tile_data  = []
    tile_style = []
    col_w      = CONTENT_W / 5

    for col_idx, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
        count = by_sev.get(sev, 0)
        bg    = SEV_COLORS.get(sev, C.INFO)
        tile_data.append([
            Paragraph(str(count), styles["metric_number"]),
            Paragraph(sev, styles["metric_label"]),
        ])
        tile_style += [
            ("BACKGROUND",   (col_idx, 0), (col_idx, 1), bg),
            ("TEXTCOLOR",    (col_idx, 0), (col_idx, 1), C.WHITE),
        ]

    # Lay tiles in a single-row 5-col table
    tiles_row = [[
        Table([[Paragraph(str(by_sev.get(sev, 0)), styles["metric_number"])],
               [Paragraph(sev, styles["metric_label"])]],
              colWidths=[col_w - 2],
              style=TableStyle([
                  ("BACKGROUND", (0,0), (-1,-1), SEV_COLORS.get(sev, C.INFO)),
                  ("TEXTCOLOR",  (0,0), (-1,-1), C.WHITE),
                  ("ALIGN",      (0,0), (-1,-1), "CENTER"),
                  ("TOPPADDING", (0,0), (-1,-1), 10),
                  ("BOTTOMPADDING", (0,0), (-1,-1), 10),
                  ("LEFTPADDING", (0,0), (-1,-1), 4),
                  ("RIGHTPADDING", (0,0), (-1,-1), 4),
                  ("ROWBACKGROUNDS", (0,0), (-1,-1),
                   [SEV_COLORS.get(sev, C.INFO)]),
              ]))
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ]]
    tiles_table = Table(tiles_row,
                        colWidths=[col_w]*5,
                        hAlign="LEFT")
    tiles_table.setStyle(TableStyle([
        ("LEFTPADDING",   (0,0), (-1,-1), 2),
        ("RIGHTPADDING",  (0,0), (-1,-1), 2),
        ("TOPPADDING",    (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(tiles_table)
    story.append(_vspace(16))

    # ── Charts side by side ───────────────────────────────────────────────────
    try:
        pie_buf  = _severity_pie_chart(by_sev)
        bar_buf  = _severity_bar_chart(by_sev)

        pie_img  = Image(pie_buf,
                         width=CONTENT_W * 0.57, height=62*mm)
        bar_img  = Image(bar_buf,
                         width=CONTENT_W * 0.38, height=55*mm)

        chart_table = Table(
            [[pie_img, bar_img]],
            colWidths=[CONTENT_W * 0.57, CONTENT_W * 0.43],
            hAlign="LEFT",
        )
        chart_table.setStyle(TableStyle([
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
            ("TOPPADDING",   (0,0), (-1,-1), 0),
            ("BOTTOMPADDING",(0,0), (-1,-1), 0),
        ]))
        story.append(chart_table)
        story.append(Paragraph(
            "Figure 1  Severity distribution of findings",
            styles["caption"],
        ))
    except Exception as exc:
        logger.warning("Chart generation failed: %s — skipping charts.", exc)
        story.append(Paragraph(
            "[Chart unavailable — see severity tile summary above]",
            styles["body_small"],
        ))

    story.append(PageBreak())


def _build_finding(story: list, styles: dict, vuln: dict, idx: int) -> None:
    """
    Append a single vulnerability finding block to *story*.

    Each block is wrapped in KeepTogether for the header + description so
    short findings don't get their title orphaned at a page bottom.
    """
    sev      = _safe_str(vuln.get("severity", "INFO")).upper()
    title    = _safe_str(vuln.get("title", "Untitled Finding"), 100)
    category = _safe_str(vuln.get("category", "—"), 60)
    desc     = _safe_str(vuln.get("description", ""))
    remed    = _safe_str(vuln.get("remediation", ""))
    evidence = vuln.get("evidence", [])
    sev_col  = SEV_COLORS.get(sev, C.INFO)

    # ── Finding header band ───────────────────────────────────────────────────
    header_table = Table(
        [[
            Paragraph(sev, ParagraphStyle(
                "sev_badge_pdf",
                fontName="Helvetica-Bold",
                fontSize=8,
                textColor=C.WHITE,
            )),
            Paragraph(title, ParagraphStyle(
                "find_title",
                fontName="Helvetica-Bold",
                fontSize=10.5,
                textColor=C.WHITE,
                leading=14,
            )),
            Paragraph(category, ParagraphStyle(
                "find_cat",
                fontName="Helvetica",
                fontSize=8,
                textColor=colors.HexColor("#c8d4e8"),
                alignment=TA_RIGHT,
            )),
        ]],
        colWidths=[20*mm, CONTENT_W - 44*mm, 22*mm],
        hAlign="LEFT",
    )
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), sev_col),
        ("LEFTPADDING",   (0, 0), (0, 0), 6),
        ("LEFTPADDING",   (1, 0), (1, 0), 8),
        ("RIGHTPADDING",  (2, 0), (2, 0), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS",(0, 0), (-1, -1), [3, 3, 3, 3]),
    ]))

    header_spacer = _vspace(4)

    # ── Description ───────────────────────────────────────────────────────────
    desc_paras = [
        Paragraph("Description", styles["h3"]),
        Paragraph(desc.replace("\n", " "), styles["body"]),
        _vspace(6),
    ]

    # ── Remediation ──────────────────────────────────────────────────────────
    remed_paras = [
        Paragraph("Remediation", styles["h3"]),
        Paragraph(remed.replace("\n", " "), styles["body"]),
        _vspace(6),
    ]

    # Group header + description so they don't orphan
    keep = [header_table, header_spacer] + desc_paras
    story.append(KeepTogether(keep))
    story.extend(remed_paras)

    # ── Evidence table ────────────────────────────────────────────────────────
    if evidence:
        story.append(Paragraph("Evidence", styles["h3"]))

        ev_header = [
            Paragraph("#",            styles["label"]),
            Paragraph("File",         styles["label"]),
            Paragraph("Line",         styles["label"]),
            Paragraph("Match Preview",styles["label"]),
        ]
        ev_rows = [ev_header]

        for i, ev in enumerate(evidence, start=1):
            raw_file    = _safe_str(ev.get("file", "—"), 80)
            line_no     = ev.get("line_number", 0)
            preview     = _safe_str(ev.get("match_preview", "—"), 60)
            line_str    = str(line_no) if line_no and line_no > 0 else "—"

            # Show last 2 path segments to avoid wrapping
            parts = re.split(r"[/\\]", raw_file)
            short_file = "/".join(parts[-2:]) if len(parts) > 2 else raw_file

            ev_rows.append([
                Paragraph(str(i),   styles["mono"]),
                Paragraph(short_file, styles["mono"]),
                Paragraph(line_str, styles["mono"]),
                Paragraph(preview,  styles["mono"]),
            ])

        ev_col_widths = [8*mm, CONTENT_W * 0.38, 12*mm, CONTENT_W - 8*mm - CONTENT_W * 0.38 - 12*mm]
        ev_table = Table(ev_rows, colWidths=ev_col_widths, hAlign="LEFT",
                         repeatRows=1)
        ev_style = TableStyle([
            # Header row
            ("BACKGROUND",    (0, 0), (-1, 0), C.TABLE_HEADER),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C.WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0), 8),
            # Data rows
            ("FONTNAME",      (0, 1), (-1, -1), "Courier"),
            ("FONTSIZE",      (0, 1), (-1, -1), 7.5),
            ("TEXTCOLOR",     (0, 1), (-1, -1), C.BODY_TEXT),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C.WHITE, C.TABLE_ALT]),
            # Grid
            ("GRID",          (0, 0), (-1, -1), 0.4, C.TABLE_BORDER),
            ("BOX",           (0, 0), (-1, -1), 0.8, C.MID_GREY),
            # Padding
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ])
        ev_table.setStyle(ev_style)
        story.append(ev_table)

    story.append(_vspace(14))
    story.append(_hr(0.5, C.LIGHT_GREY))
    story.append(_vspace(10))


def _build_findings(story: list, styles: dict, vulns: list) -> None:
    """Section 2 — iterate all vulnerabilities."""
    story.append(Paragraph("2  Vulnerability Findings", styles["h1"]))
    story.append(_hr(1.2, C.ACCENT))
    story.append(_vspace(6))

    if not vulns:
        story.append(Paragraph(
            "No vulnerabilities were identified in this scan.",
            styles["body"],
        ))
        story.append(PageBreak())
        return

    for idx, vuln in enumerate(vulns, start=1):
        _build_finding(story, styles, vuln, idx)

    story.append(PageBreak())


def _build_permissions(story: list, styles: dict, permissions: list,
                        dangerous: list) -> None:
    """Appendix section listing all declared permissions."""
    story.append(Paragraph("3  Permission Inventory", styles["h1"]))
    story.append(_hr(1.2, C.ACCENT))
    story.append(_vspace(6))

    if not permissions:
        story.append(Paragraph(
            "No permissions were found in AndroidManifest.xml.",
            styles["body"],
        ))
        return

    dangerous_set = set(dangerous or [])
    perm_header   = [
        Paragraph("Permission",           styles["label"]),
        Paragraph("Classification",       styles["label"]),
    ]
    perm_rows = [perm_header]

    for perm in sorted(permissions):
        is_danger = perm in dangerous_set
        cls_text  = "DANGEROUS" if is_danger else "Normal"
        cls_style = ParagraphStyle(
            "perm_cls",
            parent=styles["body_small"],
            textColor=C.CRITICAL if is_danger else C.BODY_TEXT,
            fontName="Helvetica-Bold" if is_danger else "Helvetica",
        )
        perm_rows.append([
            Paragraph(_safe_str(perm), styles["mono"]),
            Paragraph(cls_text, cls_style),
        ])

    perm_table = Table(
        perm_rows,
        colWidths=[CONTENT_W * 0.78, CONTENT_W * 0.22],
        hAlign="LEFT",
        repeatRows=1,
    )
    perm_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C.TABLE_HEADER),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C.WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C.WHITE, C.TABLE_ALT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C.TABLE_BORDER),
        ("BOX",           (0, 0), (-1, -1), 0.8, C.MID_GREY),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(perm_table)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(report_data: dict) -> bytes:
    """
    Generate a professional multi-page PDF security audit report.

    Parameters
    ----------
    report_data:
        The full ``MappedReport`` dict from ``vulnerability_mapper.generate_report``.
        Must contain:
            - app_profile  (package_name, min_sdk, target_sdk, signature_info,
                            permissions)
            - summary      (total_vulnerabilities, by_severity, dangerous_permissions)
            - vulnerabilities  (list of Vulnerability TypedDicts)

    Returns
    -------
    bytes
        Raw PDF byte string, ready for streaming to an HTTP response or saving
        to disk.

    Raises
    ------
    Exception
        Any ReportLab or matplotlib exception is logged and re-raised; the
        caller (FastAPI endpoint) is responsible for converting to a 500 HTTP
        response.
    """
    logger.info("PDF generation started.")

    app_profile  = report_data.get("app_profile", {}) or {}
    summary      = report_data.get("summary", {}) or {}
    vulns        = report_data.get("vulnerabilities", []) or []
    permissions  = app_profile.get("permissions", []) or []
    dangerous    = summary.get("dangerous_permissions", []) or []

    pkg_name  = _safe_str(app_profile.get("package_name", "Unknown Application"), 80)
    scan_date = datetime.now(tz=timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    styles = _build_styles()
    buf    = io.BytesIO()
    doc    = _make_doc(buf, pkg_name, scan_date)

    story: list = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(NextPageTemplate("cover"))
    _build_cover(story, styles, pkg_name, scan_date, summary)

    # ── ToC ───────────────────────────────────────────────────────────────────
    _build_toc(story, styles, vulns)

    # ── Executive Summary ─────────────────────────────────────────────────────
    _build_executive_summary(story, styles, app_profile, summary)

    # ── Findings ──────────────────────────────────────────────────────────────
    _build_findings(story, styles, vulns)

    # ── Permissions ───────────────────────────────────────────────────────────
    _build_permissions(story, styles, permissions, dangerous)

    # ── Build ─────────────────────────────────────────────────────────────────
    doc.build(story)
    pdf_bytes = buf.getvalue()

    logger.info(
        "PDF generation complete — %d pages approx, %d bytes.",
        len(vulns) + 4,
        len(pdf_bytes),
    )
    return pdf_bytes
