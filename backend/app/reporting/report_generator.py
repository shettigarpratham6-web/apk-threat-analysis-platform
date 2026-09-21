"""Phase 11: Forensic Report Generator (HTML/PDF)"""
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
    Generates a professional PDF forensic report using ReportLab.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        doc = SimpleDocTemplate(pdf_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = []

        # Styles
        title_style = ParagraphStyle("TitleStyle", parent=styles["Heading1"], fontSize=18, leading=22, textColor=colors.HexColor("#0f172a"))
        h2_style = ParagraphStyle("H2Style", parent=styles["Heading2"], fontSize=13, leading=16, textColor=colors.HexColor("#1e293b"))
        body_style = ParagraphStyle("BodyStyle", parent=styles["BodyText"], fontSize=10, leading=14, textColor=colors.HexColor("#334155"))
        code_style = ParagraphStyle("CodeStyle", parent=styles["Code"], fontSize=8, leading=10, textColor=colors.HexColor("#475569"))

        # Cover Page
        story.append(Paragraph("APK Threat Analysis Platform - Forensic Report", title_style))
        story.append(Spacer(1, 14))
        
        meta = context.get("metadata", {})
        story.append(Paragraph(f"<b>APK Name:</b> {meta.get('filename')} <br/>"
                               f"<b>Package Name:</b> {context.get('manifest_analysis', {}).get('metadata', {}).get('package_name', 'Unknown')} <br/>"
                               f"<b>APK SHA256:</b> {meta.get('sha256')} <br/>"
                               f"<b>Date:</b> {context.get('generated_date')}", body_style))
        story.append(Spacer(1, 20))

        # Risk Score Section
        risk = context.get("risk_analysis", {})
        r_score = risk.get("score", 0)
        r_level = risk.get("level", "Unknown")
        
        banner_color = "#16a34a" # Green
        if r_score >= 80: banner_color = "#dc2626"
        elif r_score >= 60: banner_color = "#ea580c"
        elif r_score >= 40: banner_color = "#ca8a04"

        banner_table = Table([[f"THREAT LEVEL: {r_level.upper()}", f"SCORE: {r_score} / 100"]], colWidths=[380, 160])
        banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(banner_color)),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ('PADDING', (0, 0), (-1, -1), 15),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 20))

        # Executive Summary
        story.append(Paragraph("Executive Summary", h2_style))
        story.append(Spacer(1, 6))
        story.append(Paragraph("This document contains the automated static cyber-forensic analysis results. "
                               "The analysis engine extracted the APK, parsed the AndroidManifest.xml, analyzed the DEX bytecode, "
                               "scanned resources for secrets, verified native libraries, and performed YARA signature matching.", body_style))
        story.append(Spacer(1, 10))

        # Contributing Risk Factors
        story.append(Paragraph("Risk Contributing Factors", h2_style))
        story.append(Spacer(1, 6))
        factors = risk.get("factors", [])
        if not factors:
            story.append(Paragraph("No significant risk factors found.", body_style))
        for factor in factors:
            story.append(Paragraph(f"• {factor}", body_style))
            story.append(Spacer(1, 3))
        story.append(Spacer(1, 14))

        # Security Recommendations
        story.append(Paragraph("Security Recommendations", h2_style))
        story.append(Spacer(1, 6))
        recs = risk.get("recommendations", [])
        if not recs:
            story.append(Paragraph("No specific recommendations.", body_style))
        for rec in recs:
            story.append(Paragraph(f"✓ {rec}", body_style))
            story.append(Spacer(1, 3))
        story.append(Spacer(1, 20))

        # Summary Table
        story.append(Paragraph("Multi-Stage Summary Findings", h2_style))
        story.append(Spacer(1, 6))

        mani_perms = context.get("manifest_analysis", {}).get("permissions", [])
        code_urls = context.get("code_analysis", {}).get("network_indicators", {}).get("urls", [])
        code_apis = context.get("code_analysis", {}).get("suspicious_apis", [])
        resources_secrets = context.get("resource_analysis", {}).get("secrets", [])
        native_libs = context.get("native_library_analysis", {}).get("libraries", [])
        yara_matches = context.get("yara_matches", [])

        summary_data = [
            ["Analysis Stage", "Metrics Identified"],
            ["Manifest Analysis", f"{len(mani_perms)} permissions requested"],
            ["DEX Code Analysis", f"{len(code_urls)} URLs, {len(code_apis)} suspicious APIs"],
            ["Resource Analysis", f"{len(resources_secrets)} exposed secrets/keys"],
            ["Native Library Analysis", f"{len(native_libs)} native libraries (.so)"],
            ["YARA Signature Check", f"{len(yara_matches)} malware signatures matched"],
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
        logger.info(f"Generated PDF report at: {pdf_path}")
    except Exception as exc:
        logger.error(f"Failed to generate PDF using ReportLab: {exc}")

def generate_report(apk_id: str) -> Dict[str, str]:
    """
    Loads static analysis artifacts for apk_id, renders Jinja2 template to HTML,
    and converts to PDF. Returns paths to JSON, HTML, and PDF.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(TEMPLATES_DIR, exist_ok=True)

    json_file = os.path.join(RESULTS_DIR, f"{apk_id}_report.json")
    html_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.html")
    pdf_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.pdf")

    if not os.path.exists(json_file):
        raise FileNotFoundError(f"Analysis JSON for {apk_id} not found. Ensure analysis is completed.")

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Attach timestamp for report
    data["generated_date"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Render HTML template using Jinja2
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    
    # Check if template exists, if not we will just skip HTML/PDF temporarily 
    # (The frontend UI can handle it or we assume template is there)
    try:
        template = env.get_template("report_template.html")
        rendered_html = template.render(**data)
        
        with open(html_path, "w", encoding="utf-8") as hf:
            hf.write(rendered_html)
            
    except Exception as e:
        logger.error(f"Template rendering failed: {e}")
        # Write a very basic fallback HTML if template is missing so pipeline doesn't break
        with open(html_path, "w", encoding="utf-8") as hf:
            hf.write("<html><body><h1>Report Rendering Error</h1></body></html>")

    # Generate PDF Document
    try:
        from weasyprint import HTML
        HTML(string=rendered_html).write_pdf(pdf_path)
    except Exception as wp_exc:
        logger.warning(f"WeasyPrint failed. Triggering ReportLab fallback. {wp_exc}")
        _fallback_pdf_generation(data, pdf_path)

    return {
        "apk_id": apk_id,
        "json_report": f"/api/report/download/{apk_id}?format=json",
        "html_report": f"/api/report/view/{apk_id}",
        "pdf_report": f"/api/report/download/{apk_id}?format=pdf"
    }
