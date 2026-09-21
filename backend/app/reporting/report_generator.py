"""Module for rendering Jinja2 forensic HTML reports and converting them to PDF format."""

import datetime
import json
import logging
import os
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger("report_generator")

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))
TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "templates"))


def _fallback_pdf_generation(context: Dict[str, Any], pdf_path: str) -> None:
    """
    Fallback PDF generator using reportlab if weasyprint library is unavailable or encounters environment errors.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        doc = SimpleDocTemplate(pdf_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle("TitleStyle", parent=styles["Heading1"], fontSize=18, leading=22, textColor=colors.HexColor("#0f172a"))
        h2_style = ParagraphStyle("H2Style", parent=styles["Heading2"], fontSize=13, leading=16, textColor=colors.HexColor("#1e293b"))
        body_style = ParagraphStyle("BodyStyle", parent=styles["BodyText"], fontSize=10, leading=14, textColor=colors.HexColor("#334155"))

        story.append(Paragraph("APK Threat Analysis Forensic Report", title_style))
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"<b>Package:</b> {context.get('package_name')} | <b>APK ID:</b> {context.get('apk_id')} | <b>Date:</b> {context.get('generated_date')}", body_style))
        story.append(Spacer(1, 14))

        # Risk Banner Table
        r_score = context.get("risk_score", 0)
        r_label = context.get("risk_label", "Unknown")
        banner_table = Table([[f"RISK ASSESSMENT: {r_label.upper()}", f"{r_score} / 100"]], colWidths=[380, 160])
        banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#dc2626" if r_score > 75 else "#ea580c" if r_score > 50 else "#ca8a04" if r_score > 25 else "#16a34a")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 14))

        # Contributing Factors
        story.append(Paragraph("Key Risk Contributing Factors", h2_style))
        story.append(Spacer(1, 6))
        for factor in context.get("contributing_factors", []):
            story.append(Paragraph(f"• {factor}", body_style))
            story.append(Spacer(1, 3))
        story.append(Spacer(1, 10))

        # Summary Table
        story.append(Paragraph("Multi-Stage Summary Findings", h2_style))
        story.append(Spacer(1, 6))

        summary_data = [
            ["Analysis Stage", "Key Indicators Identified"],
            ["Manifest Permissions", f"{len(context.get('manifest', {}).get('declared_dangerous_permissions', []))} dangerous permissions"],
            ["Code Analysis", f"{len(context.get('code_analysis', {}).get('urls', []))} URLs, {len(context.get('code_analysis', {}).get('suspicious_apis', []))} suspicious APIs"],
            ["Signature Check", f"{len(context.get('signature_check', {}).get('yara_matches', []))} YARA rule matches"],
            ["C2 Traffic Detection", f"{len(context.get('c2_detection', {}).get('suspected_c2_hosts', []))} suspected C2 hosts"],
            ["Server Reputation", f"{len(context.get('server_reputation', {}).get('checked', []))} servers checked"],
        ]
        sum_table = Table(summary_data, colWidths=[200, 340])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(sum_table)

        doc.build(story)
        logger.info(f"Generated fallback PDF report at: {pdf_path}")
    except Exception as exc:
        logger.error(f"Failed to generate fallback PDF using ReportLab: {exc}")


def generate_report(apk_id: str) -> str:
    """
    Loads correlated analysis artifacts for apk_id, renders report_template.html Jinja2 template,
    saves raw HTML file to backend/results/<apk_id>_report.html, and converts it to PDF format
    at backend/results/<apk_id>_report.pdf.

    :param apk_id: Unique identifier for the APK analysis session.
    :return: Absolute file path to the generated PDF report.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)

    correlation_file = os.path.join(RESULTS_DIR, f"{apk_id}_correlation.json")
    static_file = os.path.join(RESULTS_DIR, f"{apk_id}_static.json")
    dynamic_file = os.path.join(RESULTS_DIR, f"{apk_id}_dynamic.json")
    c2_file = os.path.join(RESULTS_DIR, f"{apk_id}_c2.json")
    servers_file = os.path.join(RESULTS_DIR, f"{apk_id}_servers.json")

    # Load correlation data
    correlation_data = {}
    if os.path.exists(correlation_file):
        try:
            with open(correlation_file, "r", encoding="utf-8") as f:
                correlation_data = json.load(f)
        except Exception as exc:
            logger.warning(f"Could not read correlation JSON for '{apk_id}': {exc}")

    # Load detailed stage outputs if present
    static_data = {}
    if os.path.exists(static_file):
        try:
            with open(static_file, "r", encoding="utf-8") as f:
                static_data = json.load(f).get("static_analysis", {})
        except Exception:
            pass

    c2_data = {}
    if os.path.exists(c2_file):
        try:
            with open(c2_file, "r", encoding="utf-8") as f:
                c2_data = json.load(f)
        except Exception:
            pass

    servers_data = {}
    if os.path.exists(servers_file):
        try:
            with open(servers_file, "r", encoding="utf-8") as f:
                servers_data = json.load(f)
        except Exception:
            pass

    risk_assessment = correlation_data.get("risk_assessment", {})

    context = {
        "apk_id": apk_id,
        "package_name": correlation_data.get("package_name", static_data.get("package_name", "unknown.package")),
        "generated_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": risk_assessment.get("risk_score", 0),
        "risk_label": risk_assessment.get("risk_label", "Low Risk"),
        "score_breakdown": risk_assessment.get("score_breakdown", {}),
        "contributing_factors": risk_assessment.get("contributing_factors", ["No significant indicators reported."]),
        "manifest": static_data.get("manifest", {}),
        "code_analysis": static_data.get("code_analysis", {}),
        "signature_check": static_data.get("signature_check", {}),
        "dynamic_summary": correlation_data.get("dynamic_summary", {}),
        "c2_detection": c2_data if c2_data else correlation_data.get("c2_summary", {}),
        "server_reputation": servers_data if servers_data else correlation_data.get("server_summary", {}),
    }

    # Render HTML template using Jinja2
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template("report_template.html")
    rendered_html = template.render(**context)

    # Save raw rendered HTML artifact
    html_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.html")
    with open(html_path, "w", encoding="utf-8") as hf:
        hf.write(rendered_html)
    logger.info(f"Saved rendered HTML report to: {html_path}")

    # Render PDF document using WeasyPrint (with ReportLab fallback)
    pdf_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.pdf")

    try:
        from weasyprint import HTML
        HTML(string=rendered_html).write_pdf(pdf_path)
        logger.info(f"Successfully generated PDF report via WeasyPrint at: {pdf_path}")
    except Exception as wp_exc:
        logger.warning(f"WeasyPrint PDF rendering failed or GTK library missing ({wp_exc}). Triggering ReportLab fallback PDF generator.")
        _fallback_pdf_generation(context, pdf_path)

    return pdf_path
