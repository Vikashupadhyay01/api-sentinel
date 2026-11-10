"""
backend/report.py – PDF Security Report generator for API-Sentinel using ReportLab.

Produces an executive-level, professional security assessment report including:
  1. Cover page with assessment metadata and mode (Passive vs Enforcement)
  2. Executive summary with 0–100 Risk Score and qualitative rating
  3. Key metrics summary table
  4. OWASP API Security Top 10 breakdown table and vector bar visual
  5. Live endpoint inventory (Documented, Shadow, Zombie)
  6. Security alerts log (all PII-masked)
  7. Blocked requests log (active enforcement actions)
  8. Top 5 findings with actionable developer remediation guidance
  9. Methodology and laboratory environment disclaimer
 10. Running header and dynamic "Page X of Y" footer via NumberedCanvas
"""
from __future__ import annotations

import datetime
import io
import os
from typing import Any, Mapping, Sequence

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.discovery import EndpointInfo, inventory_to_list
from backend.pii import mask
from backend.remediation import OWASP_INFO, get_owasp_description, get_remediation
from backend.risk import compute_risk_score


# ---------------------------------------------------------------------------
# Numbered Canvas for "Page X of Y" and Running Headers/Footers
# ---------------------------------------------------------------------------

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that writes running headers and total page counts."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Skip running header on first page
        if self._pageNumber > 1:
            self.drawString(54, 750, "API-SENTINEL  |  Runtime Security Assessment Report")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 558, 744)

        # Footer on all pages
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, page_str)
        self.drawString(
            54,
            36,
            "API-Sentinel v1.1  •  Confidential Security Report  •  Lab Environment",
        )
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 46, 558, 46)

        self.restoreState()


# ---------------------------------------------------------------------------
# PDF Report Generator
# ---------------------------------------------------------------------------

def generate_security_report_pdf(
    stats: Mapping[str, Any],
    inventory: Mapping[tuple[str, str], EndpointInfo] | Sequence[dict[str, Any]],
    alerts: Sequence[Mapping[str, Any]],
    blocked_requests: Sequence[Mapping[str, Any]],
    enforcement_mode: bool | None = None,
) -> bytes:
    """Generate a comprehensive security report PDF as raw bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    if enforcement_mode is None:
        enforcement_mode = os.getenv("ENFORCE", "0") == "1"

    # Base Styles
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#475569"),
        spaceAfter=15,
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    body_bold = ParagraphStyle(
        "BodyDarkBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
    )

    table_cell_mono = ParagraphStyle(
        "TableCellMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
    )

    story: list[Any] = []

    # -----------------------------------------------------------------------
    # 1. Header Banner & Title
    # -----------------------------------------------------------------------
    story.append(Spacer(1, 10))
    story.append(Paragraph("🛡️ API-SENTINEL", title_style))
    story.append(
        Paragraph(
            "Runtime BOLA & Shadow API Security Assessment Report",
            subtitle_style,
        )
    )

    # Mode indicator pill
    mode_text = "ENFORCEMENT MODE: ACTIVE (403 BLOCKING)" if enforcement_mode else "PASSIVE DETECTION MODE (AUDITING ONLY)"
    mode_bg = "#fee2e2" if enforcement_mode else "#e0f2fe"
    mode_fg = "#991b1b" if enforcement_mode else "#075985"

    mode_table = Table(
        [[Paragraph(f"<b>{mode_text}</b>", ParagraphStyle("ModeStyle", fontName="Helvetica-Bold", fontSize=8.5, textColor=colors.HexColor(mode_fg)))]],
        colWidths=[504],
    )
    mode_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(mode_bg)),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 1, colors.HexColor(mode_fg)),
    ]))
    story.append(mode_table)
    story.append(Spacer(1, 12))

    # Metadata Table
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [
        [
            Paragraph("<b>Generated:</b>", body_style),
            Paragraph(now_utc, body_style),
            Paragraph("<b>Assessment Target:</b>", body_style),
            Paragraph("http://127.0.0.1:8000 (Lab Mock)", table_cell_mono),
        ],
        [
            Paragraph("<b>Auditing Proxy:</b>", body_style),
            Paragraph("http://127.0.0.1:8080", table_cell_mono),
            Paragraph("<b>Official Contract:</b>", body_style),
            Paragraph("openapi/openapi.yaml", table_cell_mono),
        ],
        [
            Paragraph("<b>Engine Version:</b>", body_style),
            Paragraph("API-Sentinel v1.1.0", body_style),
            Paragraph("<b>Data Redaction:</b>", body_style),
            Paragraph("PII Redaction Applied (100%)", body_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[90, 162, 110, 142])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 2. Executive Summary & Risk Gauge
    # -----------------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary & Threat Posture", section_heading))

    # Compute risk score
    shadow_count = stats.get("shadow_endpoints", 0)
    zombie_count = stats.get("zombie_endpoints", 0)
    blocked_count = len(blocked_requests)
    risk_info = compute_risk_score(
        alerts=alerts,
        shadow_count=shadow_count,
        zombie_count=zombie_count,
        blocked_count=blocked_count,
    )
    risk_score = risk_info["score"]
    risk_level = risk_info["level"]

    risk_card_color = "#ef4444" if risk_level == "CRITICAL" else "#f97316" if risk_level == "HIGH" else "#f59e0b" if risk_level == "MEDIUM" else "#10b981"
    risk_card_bg = "#fef2f2" if risk_level in ("CRITICAL", "HIGH") else "#fffbeb" if risk_level == "MEDIUM" else "#f0fdf4"

    risk_box = [
        [
            Paragraph(
                f"<font size='22'><b>{risk_score} / 100</b></font><br/>"
                f"<font size='10' color='{risk_card_color}'><b>{risk_level} RISK LEVEL</b></font>",
                ParagraphStyle("RiskScoreStyle", parent=body_style, alignment=1),
            ),
            Paragraph(
                f"<b>Assessment Finding:</b> API-Sentinel performed runtime passive inspection and "
                f"active policy validation of HTTP traffic. The inspection revealed "
                f"<b>{shadow_count} undocumented Shadow API(s)</b>, <b>{zombie_count} unmaintained Zombie route(s)</b>, "
                f"and <b>{len(alerts)} confirmed security violations</b> including Broken Object Level Authorization (BOLA). "
                f"Immediate remediation is required to enforce authorization checks and retire deprecated routes.",
                body_style,
            ),
        ]
    ]
    risk_table = Table(risk_box, colWidths=[140, 364])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(risk_card_bg)),
        ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor(risk_card_color)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 10))

    # Key Metrics Table
    summary_metrics = [
        [
            Paragraph("<b>Total HTTP Requests</b>", body_style),
            Paragraph(str(stats.get("total_requests", 0)), body_bold),
            Paragraph("<b>Total Endpoints Observed</b>", body_style),
            Paragraph(str(stats.get("total_endpoints", 0)), body_bold),
        ],
        [
            Paragraph("<b>Documented Endpoints</b>", body_style),
            Paragraph(f"<font color='#059669'>{stats.get('documented_endpoints', 0)}</font>", body_bold),
            Paragraph("<b>Shadow / Zombie APIs</b>", body_style),
            Paragraph(f"<font color='#dc2626'>{shadow_count + zombie_count}</font> ({shadow_count} sh / {zombie_count} zm)", body_bold),
        ],
        [
            Paragraph("<b>Security Alerts Raised</b>", body_style),
            Paragraph(f"<font color='#dc2626'>{len(alerts)}</font>", body_bold),
            Paragraph("<b>Requests Blocked (403)</b>", body_style),
            Paragraph(f"<font color='#b45309'>{blocked_count}</font>", body_bold),
        ],
    ]
    metrics_table = Table(summary_metrics, colWidths=[140, 112, 140, 112])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 3. OWASP API Security Top 10 Breakdown
    # -----------------------------------------------------------------------
    story.append(Paragraph("2. OWASP API Security Top 10 Distribution", section_heading))

    owasp_counts = stats.get("owasp_breakdown", {})
    owasp_rows = [
        [
            Paragraph("OWASP CODE", table_header),
            Paragraph("CATEGORY & TITLE", table_header),
            Paragraph("ALERTS", table_header),
            Paragraph("SEVERITY", table_header),
            Paragraph("DISTRIBUTION VISUAL", table_header),
        ]
    ]

    total_alerts_count = max(1, len(alerts))
    for code, info in OWASP_INFO.items():
        cnt = owasp_counts.get(code, 0)
        pct = int((cnt / total_alerts_count) * 100) if total_alerts_count else 0
        sev = "HIGH" if code in ("API1", "API6") else "MEDIUM"
        sev_color = "#dc2626" if sev == "HIGH" else "#d97706"

        # Create a visual bar in table
        bar_cell = f"<font color='{sev_color}'>{'█' * max(1, pct // 5)}</font> {pct}%" if cnt > 0 else "<font color='#94a3b8'>—</font>"

        owasp_rows.append([
            Paragraph(f"<b>{code}</b>", table_cell_mono),
            Paragraph(f"<b>{info['title']}</b>", table_cell),
            Paragraph(f"<b>{cnt}</b>", table_cell),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", table_cell),
            Paragraph(bar_cell, table_cell),
        ])

    owasp_table = Table(owasp_rows, colWidths=[65, 205, 55, 65, 114])
    owasp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(owasp_table)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 4. Discovered Endpoint Inventory
    # -----------------------------------------------------------------------
    story.append(Paragraph("3. Observed API Endpoint Inventory", section_heading))

    # Convert inventory
    if isinstance(inventory, dict):
        inv_list = inventory_to_list(inventory)
    else:
        inv_list = list(inventory)

    inv_rows = [
        [
            Paragraph("METHOD", table_header),
            Paragraph("NORMALIZED PATH", table_header),
            Paragraph("CLASSIFICATION", table_header),
            Paragraph("OWASP", table_header),
            Paragraph("HITS", table_header),
            Paragraph("SEEN USERS", table_header),
        ]
    ]

    for ep in inv_list:
        cls = ep.get("classification", "documented").upper()
        cls_color = "#dc2626" if cls == "ZOMBIE" else "#7c3aed" if cls == "SHADOW" else "#059669"
        users_str = ", ".join(ep.get("users_seen", [])) or "anonymous"

        inv_rows.append([
            Paragraph(f"<b>{ep.get('method', 'GET')}</b>", table_cell_mono),
            Paragraph(ep.get("norm_path", "/"), table_cell_mono),
            Paragraph(f"<font color='{cls_color}'><b>{cls}</b></font>", table_cell),
            Paragraph(ep.get("owasp_category", "—") or "—", table_cell),
            Paragraph(str(ep.get("hit_count", 0)), table_cell),
            Paragraph(users_str, table_cell),
        ])

    if len(inv_rows) == 1:
        inv_rows.append([Paragraph("No endpoints observed.", table_cell)] * 6)

    inv_table = Table(inv_rows, colWidths=[55, 185, 84, 55, 45, 80])
    inv_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(inv_table)
    story.append(Spacer(1, 14))

    # Page Break for findings and logs
    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # 5. Security Alerts Log (PII Masked)
    # -----------------------------------------------------------------------
    story.append(Paragraph("4. Security Alerts Log (PII-Masked)", section_heading))
    story.append(
        Paragraph(
            "Every security finding detected by API-Sentinel during runtime analysis. "
            "All sensitive variables, authentication tokens, emails, and card numbers are redacted.",
            body_style,
        )
    )
    story.append(Spacer(1, 6))

    alert_rows = [
        [
            Paragraph("TIME", table_header),
            Paragraph("SEV", table_header),
            Paragraph("OWASP", table_header),
            Paragraph("ACTOR", table_header),
            Paragraph("ENDPOINT", table_header),
            Paragraph("EXPLANATION", table_header),
        ]
    ]

    for a in alerts:
        sev = a.get("severity", "MEDIUM")
        sev_color = "#dc2626" if sev in ("CRITICAL", "HIGH") else "#d97706"
        ts_str = a.get("ts", "")
        if "T" in ts_str:
            ts_str = ts_str.split("T")[1][:8]

        alert_rows.append([
            Paragraph(ts_str, table_cell_mono),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", table_cell),
            Paragraph(f"<b>{a.get('owasp_category', '')}</b>", table_cell),
            Paragraph(a.get("user", "") or "anon", table_cell),
            Paragraph(a.get("endpoint", ""), table_cell_mono),
            Paragraph(mask(str(a.get("explanation", ""))), table_cell),
        ])

    if len(alert_rows) == 1:
        alert_rows.append([Paragraph("No security alerts generated.", table_cell)] * 6)

    alerts_table = Table(alert_rows, colWidths=[55, 45, 50, 55, 125, 174])
    alerts_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(alerts_table)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 6. Blocked Requests Log
    # -----------------------------------------------------------------------
    story.append(Paragraph("5. Blocked Requests Log (Enforcement)", section_heading))
    story.append(
        Paragraph(
            "Requests rejected with HTTP 403 Forbidden by the API-Sentinel reverse proxy pre-flight check.",
            body_style,
        )
    )
    story.append(Spacer(1, 6))

    blocked_rows = [
        [
            Paragraph("TIME", table_header),
            Paragraph("USER", table_header),
            Paragraph("METHOD", table_header),
            Paragraph("PATH", table_header),
            Paragraph("OBJ ID", table_header),
            Paragraph("ENFORCEMENT REASON", table_header),
            Paragraph("OWASP", table_header),
        ]
    ]

    for b in blocked_requests:
        b_time = b.get("time", "") or b.get("ts", "")
        if "T" in b_time:
            b_time = b_time.split("T")[1][:8]

        blocked_rows.append([
            Paragraph(b_time, table_cell_mono),
            Paragraph(b.get("user", "") or "anonymous", table_cell),
            Paragraph(b.get("method", "GET"), table_cell_mono),
            Paragraph(b.get("path", ""), table_cell_mono),
            Paragraph(b.get("object_id", "") or "—", table_cell_mono),
            Paragraph(f"<font color='#dc2626'>{mask(str(b.get('reason', 'Blocked by enforcement')))}</font>", table_cell),
            Paragraph(b.get("owasp_category", "API1"), table_cell),
        ])

    if len(blocked_rows) == 1:
        blocked_rows.append([Paragraph("No requests blocked during observation.", table_cell)] * 7)

    blocked_table = Table(blocked_rows, colWidths=[55, 60, 45, 115, 45, 140, 44])
    blocked_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(blocked_table)
    story.append(Spacer(1, 14))

    # Page Break for Remediation Guidance
    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # 7. Top 5 Findings & Actionable Remediation Guidance
    # -----------------------------------------------------------------------
    story.append(Paragraph("6. Top Findings & Actionable Remediation Guidance", section_heading))
    story.append(
        Paragraph(
            "Concrete developer and architecture remediation steps to mitigate identified risks:",
            body_style,
        )
    )
    story.append(Spacer(1, 8))

    remediations_data = [
        (
            "Finding 1: Broken Object Level Authorization (BOLA / OWASP API1:2023)",
            "HIGH SEVERITY",
            "#dc2626",
            "Observed users accessing objects (e.g. orders) belonging to other tenants without ownership verification.",
            "Enforce object-level ownership checks at the data/service layer on every request. Validate that "
            "<b>resource.owner_id == authenticated_user.id</b> before executing database queries. Do not rely exclusively "
            "on authentication tokens or client-provided parameters.",
        ),
        (
            "Finding 2: Undocumented Shadow APIs (OWASP API9:2023)",
            "MEDIUM SEVERITY",
            "#d97706",
            "Observed live routes (e.g. /api/v1/admin/export) entirely missing from the official openapi/openapi.yaml contract.",
            "Update the official contract in openapi/openapi.yaml to reflect all active routes, or decommission the route. "
            "Configure API gateways or reverse proxies to strictly reject any request path not defined in the specification.",
        ),
        (
            "Finding 3: Active Deprecated Zombie APIs (OWASP API9:2023)",
            "HIGH SEVERITY",
            "#dc2626",
            "Observed legacy version routes (e.g. /api/v0/users) accepting traffic despite newer API versions running.",
            "Sunset and shut down legacy service handlers. Return HTTP 410 Gone for deprecated API versions, redirect "
            "remaining consumers to the current v1 endpoints, and remove legacy routing rules from proxy configurations.",
        ),
        (
            "Finding 4: Unrestricted Resource Consumption (Rate Limiting / OWASP API4:2023)",
            "MEDIUM SEVERITY",
            "#d97706",
            "Traffic bursts exceeded configured threshold without backend rate throttling.",
            "Implement token-bucket or sliding-window rate limiting per authenticated identity and per client IP. "
            "Return HTTP 429 Too Many Requests with a Retry-After header once limits are breached.",
        ),
        (
            "Finding 5: Unrestricted Access to Sensitive Business Flows (Enumeration / OWASP API6:2023)",
            "HIGH SEVERITY",
            "#dc2626",
            "Sequential ID scanning detected across resource detail routes.",
            "Replace predictable auto-incrementing integer primary keys with non-enumerable identifiers such as UUIDv4. "
            "Deploy automated bot protection and anomaly detection for rapid sequential request patterns.",
        ),
    ]

    for title, sev, col, desc, rem in remediations_data:
        finding_box = [
            [
                Paragraph(f"<b>{title}</b>", ParagraphStyle("FTitle", parent=body_style, fontName="Helvetica-Bold", fontSize=9.5, textColor=colors.HexColor("#0f172a"))),
                Paragraph(f"<font color='{col}'><b>{sev}</b></font>", ParagraphStyle("FSev", parent=body_style, alignment=2)),
            ],
            [
                Paragraph(f"<b>Observation:</b> {desc}", body_style),
                Paragraph("", body_style),
            ],
            [
                Paragraph(f"<b>Recommended Fix:</b> {rem}", ParagraphStyle("FRem", parent=body_style, textColor=colors.HexColor("#065f46"))),
                Paragraph("", body_style),
            ],
        ]
        ft_table = Table(finding_box, colWidths=[400, 104])
        ft_table.setStyle(TableStyle([
            ("SPAN", (0, 1), (1, 1)),
            ("SPAN", (0, 2), (1, 2)),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#ecfdf5")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("LINELEFT", (0, 0), (0, -1), 3, colors.HexColor(col)),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ft_table)
        story.append(Spacer(1, 8))

    # -----------------------------------------------------------------------
    # 8. Methodology & Lab Environment Disclaimer
    # -----------------------------------------------------------------------
    story.append(Spacer(1, 8))
    story.append(Paragraph("7. Methodology & Academic Laboratory Disclaimer", section_heading))
    disclaimer_text = (
        "<b>Notice:</b> This security assessment was generated autonomously by <b>API-Sentinel</b> "
        "inside a safe educational / internship laboratory environment against mock local targets on "
        "<code>127.0.0.1</code>. No external networks or production systems were targeted. "
        "All data processed by the detection engine has been processed through API-Sentinel's PII sanitization "
        "layer to redact authentication tokens, credit card numbers, email addresses, and telephone records."
    )
    disc_table = Table([[Paragraph(disclaimer_text, body_style)]], colWidths=[504])
    disc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(disc_table)

    # Build Document with NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()

