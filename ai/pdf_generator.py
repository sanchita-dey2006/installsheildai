"""
InstallShield AI - PDF Security Report Generator
Generates professional PDF security assessment reports using ReportLab.
"""

import os
import time
import logging
from typing import Dict, Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)

logger = logging.getLogger(__name__)


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page numbers and footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Footer divider line
        self.setLineWidth(0.5)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.line(36, 40, letter[0] - 36, 40)

        # Footer text
        footer_text = "InstallShield AI - Automated Security Assessment Report | Confidential"
        page_text = f"Page {self._pageNumber} of {page_count}"

        self.drawString(36, 26, footer_text)
        self.drawRightString(letter[0] - 36, 26, page_text)
        self.restoreState()


class PDFReportGenerator:
    """Professional Security Assessment Report PDF Generator."""

    @staticmethod
    def generate_report(analysis_data: Dict[str, Any], output_path: str) -> str:
        """
        Generate a PDF security report from complete analysis data.

        :param analysis_data: Combined dictionary containing file metadata, hashes, entropy,
                              signature info, risk score, classification, explainable AI, recommendations.
        :param output_path: Destination file path for PDF.
        :return: Absolute path to the generated PDF report.
        """
        abs_output_path = os.path.abspath(output_path)
        output_dir = os.path.dirname(abs_output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception:
                filename = os.path.basename(output_path)
                abs_output_path = os.path.join("/tmp", filename)

        doc = SimpleDocTemplate(
            abs_output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=40,
            bottomMargin=50
        )

        styles = getSampleStyleSheet()

        # Custom Color Palette
        navy_dark = colors.HexColor("#0F172A")
        blue_primary = colors.HexColor("#1E40AF")
        text_dark = colors.HexColor("#1E293B")
        gray_light = colors.HexColor("#F8FAFC")
        gray_border = colors.HexColor("#E2E8F0")

        # Color mapping for risk tiers
        tier = analysis_data.get("risk_tier", "Unknown")
        if tier == "Trusted":
            tier_bg = colors.HexColor("#DCFCE7")
            tier_fg = colors.HexColor("#166534")
        elif tier == "Low Risk":
            tier_bg = colors.HexColor("#E0F2FE")
            tier_fg = colors.HexColor("#075985")
        elif tier == "Suspicious":
            tier_bg = colors.HexColor("#FEF3C7")
            tier_fg = colors.HexColor("#92400E")
        elif tier == "High Risk":
            tier_bg = colors.HexColor("#FFEDD5")
            tier_fg = colors.HexColor("#9A3412")
        else:  # Malicious
            tier_bg = colors.HexColor("#FEE2E2")
            tier_fg = colors.HexColor("#991B1B")

        # Typography Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=navy_dark
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B")
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=blue_primary,
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyTextCustom",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=text_dark
        )
        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=colors.white
        )
        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=text_dark
        )
        table_cell_bold = ParagraphStyle(
            "TableCellBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=text_dark
        )

        elements = []

        # ------------------------------------------------------------------
        # Header Banner / Branding
        # ------------------------------------------------------------------
        header_data = [
            [
                Paragraph("<b>InstallShield AI</b>", title_style),
                Paragraph(f"<b>Scan Date:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}<br/><b>Scan ID:</b> #{analysis_data.get('scan_id', 'N/A')}", subtitle_style)
            ],
            [
                Paragraph("Intelligent Binary Analysis & Security Assessment Engine", subtitle_style),
                ""
            ]
        ]
        header_table = Table(header_data, colWidths=[360, 180])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=blue_primary, spaceBefore=4, spaceAfter=12))

        # ------------------------------------------------------------------
        # Executive Summary Box
        # ------------------------------------------------------------------
        risk_score = analysis_data.get("risk_score", 0)
        category = analysis_data.get("threat_category", "Unknown Threat")

        summary_box_data = [
            [
                Paragraph("<b>EXECUTIVE VERDICT</b>", table_header_style),
                Paragraph("<b>RISK SCORE</b>", table_header_style),
                Paragraph("<b>THREAT CATEGORY</b>", table_header_style)
            ],
            [
                Paragraph(f"<font size=14 color='{tier_fg.hexval()}'><b>{tier.upper()}</b></font>", body_style),
                Paragraph(f"<font size=16 color='{tier_fg.hexval()}'><b>{risk_score} / 100</b></font>", body_style),
                Paragraph(f"<font size=11 color='{navy_dark.hexval()}'><b>{category}</b></font>", body_style)
            ]
        ]
        summary_table = Table(summary_box_data, colWidths=[180, 180, 180])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy_dark),
            ("BACKGROUND", (0, 1), (-1, 1), tier_bg),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, gray_border),
            ("BOX", (0, 0), (-1, -1), 1, tier_fg),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 12))

        # ------------------------------------------------------------------
        # File Information & Hashes Table
        # ------------------------------------------------------------------
        elements.append(Paragraph("1. File Identification & Cryptographic Hashes", section_style))

        filename = str(analysis_data.get("filename", "Unknown"))
        filepath = str(analysis_data.get("savedTo", analysis_data.get("filepath", "Unknown")))
        hashes = analysis_data.get("hashes", {})
        md5_val = hashes.get("md5", analysis_data.get("md5", "N/A"))
        sha1_val = hashes.get("sha1", analysis_data.get("sha1", "N/A"))
        sha256_val = hashes.get("sha256", analysis_data.get("sha256", "N/A"))
        meta = analysis_data.get("metadata", {})
        file_size = meta.get("file_size", "N/A")
        file_type = meta.get("file_type", "Windows Executable")
        magic_bytes = meta.get("magic_bytes", "4D5A")

        file_info_data = [
            [Paragraph("Filename", table_cell_bold), Paragraph(filename, table_cell_style), Paragraph("File Size", table_cell_bold), Paragraph(f"{file_size} bytes", table_cell_style)],
            [Paragraph("File Type", table_cell_bold), Paragraph(file_type, table_cell_style), Paragraph("Magic Bytes", table_cell_bold), Paragraph(str(magic_bytes), table_cell_style)],
            [Paragraph("MD5 Hash", table_cell_bold), Paragraph(str(md5_val), table_cell_style), Paragraph("SHA-1 Hash", table_cell_bold), Paragraph(str(sha1_val), table_cell_style)],
            [Paragraph("SHA-256 Hash", table_cell_bold), Paragraph(str(sha256_val), table_cell_style), Paragraph("File Path", table_cell_bold), Paragraph(filepath, table_cell_style)]
        ]

        file_table = Table(file_info_data, colWidths=[100, 170, 90, 180])
        file_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), gray_light),
            ("BACKGROUND", (2, 0), (2, -1), gray_light),
            ("GRID", (0, 0), (-1, -1), 0.5, gray_border),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(file_table)
        elements.append(Spacer(1, 10))

        # ------------------------------------------------------------------
        # Digital Signature & Entropy Analysis Table
        # ------------------------------------------------------------------
        elements.append(Paragraph("2. Authenticode Signature & Code Structure", section_style))

        sig_status = str(analysis_data.get("signature_status", "Unknown"))
        publisher = str(analysis_data.get("publisher", "Unknown"))
        is_trusted = analysis_data.get("is_trusted", False)
        entropy_val = analysis_data.get("entropy", 0.0)
        entropy_verdict = str(analysis_data.get("entropy_verdict", "Normal"))

        trust_label = "Verified Trusted Vendor" if is_trusted else "Unverified / Unknown Vendor"

        sig_data = [
            [Paragraph("Signature Status", table_cell_bold), Paragraph(sig_status, table_cell_style), Paragraph("Publisher Name", table_cell_bold), Paragraph(publisher, table_cell_style)],
            [Paragraph("Publisher Trust", table_cell_bold), Paragraph(trust_label, table_cell_style), Paragraph("Shannon Entropy", table_cell_bold), Paragraph(f"{entropy_val:.2f} / 8.00 ({entropy_verdict})", table_cell_style)]
        ]

        sig_table = Table(sig_data, colWidths=[100, 170, 90, 180])
        sig_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), gray_light),
            ("BACKGROUND", (2, 0), (2, -1), gray_light),
            ("GRID", (0, 0), (-1, -1), 0.5, gray_border),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(sig_table)
        elements.append(Spacer(1, 10))

        # ------------------------------------------------------------------
        # Static Indicators Table
        # ------------------------------------------------------------------
        elements.append(Paragraph("3. Static String Analysis & Security Indicators", section_style))

        apis = analysis_data.get("suspicious_apis", [])
        keywords = analysis_data.get("suspicious_keywords", [])
        urls = analysis_data.get("urls", [])

        api_text = ", ".join(apis) if apis else "None detected"
        kw_text = ", ".join(keywords) if keywords else "None detected"
        url_text = ", ".join(urls[:5]) if urls else "None detected"

        indicator_data = [
            [Paragraph("Indicator Type", table_header_style), Paragraph("Extracted Matches", table_header_style)],
            [Paragraph("Suspicious Native APIs", table_cell_bold), Paragraph(api_text, table_cell_style)],
            [Paragraph("Command Utilities / Keywords", table_cell_bold), Paragraph(kw_text, table_cell_style)],
            [Paragraph("Embedded URLs / Network IPs", table_cell_bold), Paragraph(url_text, table_cell_style)]
        ]

        indicator_table = Table(indicator_data, colWidths=[140, 400])
        indicator_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), blue_primary),
            ("GRID", (0, 0), (-1, -1), 0.5, gray_border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(indicator_table)
        elements.append(Spacer(1, 10))

        # ------------------------------------------------------------------
        # Explainable AI Analysis
        # ------------------------------------------------------------------
        elements.append(Paragraph("4. Explainable AI Assessment Narrative", section_style))

        explanation = analysis_data.get("explanation", {})
        narrative = explanation.get("summary_narrative", "Analysis concluded cleanly.")
        positives = explanation.get("positive_indicators", [])
        factors = explanation.get("risk_factors", [])

        elements.append(Paragraph(narrative, body_style))
        elements.append(Spacer(1, 6))

        if factors:
            elements.append(Paragraph("<b>Triggered Risk Factors & Weights:</b>", body_style))
            for f in factors:
                elements.append(Paragraph(f"• {f}", table_cell_style))
            elements.append(Spacer(1, 4))

        if positives:
            elements.append(Paragraph("<b>Positive Security Indicators:</b>", body_style))
            for p in positives:
                elements.append(Paragraph(f"✓ {p}", table_cell_style))
            elements.append(Spacer(1, 6))

        # ------------------------------------------------------------------
        # Actionable Recommendations Table
        # ------------------------------------------------------------------
        elements.append(Paragraph("5. Actionable Security Recommendations", section_style))

        recs = analysis_data.get("recommendations", [])
        if recs:
            rec_table_data = [[Paragraph("Priority", table_header_style), Paragraph("Recommended Action", table_header_style), Paragraph("Guidance & Details", table_header_style)]]
            for r in recs:
                lvl = r.get("level", "INFO")
                if lvl == "CRITICAL":
                    lvl_color = "#DC2626"
                elif lvl == "HIGH":
                    lvl_color = "#EA580C"
                elif lvl == "MEDIUM":
                    lvl_color = "#D97706"
                else:
                    lvl_color = "#2563EB"

                rec_table_data.append([
                    Paragraph(f"<font color='{lvl_color}'><b>{lvl}</b></font>", table_cell_bold),
                    Paragraph(r.get("action", ""), table_cell_bold),
                    Paragraph(r.get("description", ""), table_cell_style)
                ])

            rec_table = Table(rec_table_data, colWidths=[70, 160, 310])
            rec_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), navy_dark),
                ("GRID", (0, 0), (-1, -1), 0.5, gray_border),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(rec_table)

        # Build document
        doc.build(elements, canvasmaker=NumberedCanvas)
        logger.info("Generated PDF report successfully at %s", abs_output_path)

        return abs_output_path
