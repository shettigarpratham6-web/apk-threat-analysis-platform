"""FastAPI router for generating, downloading, and viewing forensic analysis reports."""

import logging
import os
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, status
from fastapi.responses import FileResponse, HTMLResponse

from backend.app.reporting.report_generator import generate_report

router = APIRouter()
logger = logging.getLogger("reporting_routes")

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


@router.post("/generate")
async def generate_forensic_report(
    apk_id: Optional[str] = Form(None),
):
    """
    Generates PDF and HTML forensic report artifacts for the given apk_id.
    """
    if not apk_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'apk_id' is required.",
        )

    correlation_file = os.path.join(RESULTS_DIR, f"{apk_id}_correlation.json")
    if not os.path.exists(correlation_file):
        # Trigger automatic correlation if missing or proceed with available data
        from backend.app.correlation.aggregator import correlate_apk

        try:
            correlate_apk(apk_id)
        except Exception as exc:
            logger.warning(f"Failed to auto-generate correlation results for '{apk_id}': {exc}")

    try:
        pdf_path = generate_report(apk_id)
        html_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.html")

        return {
            "apk_id": apk_id,
            "pdf_path": pdf_path,
            "html_path": html_path,
            "message": f"Forensic report generated successfully for apk_id '{apk_id}'.",
        }
    except Exception as err:
        logger.error(f"Error generating forensic report for apk_id '{apk_id}': {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while generating forensic report: {str(err)}",
        )


@router.get("/{apk_id}/download")
async def download_pdf_report(apk_id: str):
    """
    Downloads the compiled PDF forensic report file.
    """
    pdf_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.pdf")
    if not os.path.exists(pdf_path):
        # Try generating report if not present
        try:
            pdf_path = generate_report(apk_id)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"PDF report for apk_id '{apk_id}' not found and generation failed: {str(exc)}",
            )

    if not os.path.exists(pdf_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PDF report file for apk_id '{apk_id}' was not found.",
        )

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"{apk_id}_report.pdf",
    )


@router.get("/{apk_id}/view")
async def view_html_report(apk_id: str):
    """
    Renders raw HTML forensic report directly in the browser.
    """
    html_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.html")
    if not os.path.exists(html_path):
        try:
            generate_report(apk_id)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"HTML report for apk_id '{apk_id}' not found and generation failed: {str(exc)}",
            )

    if not os.path.exists(html_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"HTML report file for apk_id '{apk_id}' was not found.",
        )

    try:
        with open(html_path, "r", encoding="utf-8") as hf:
            html_content = hf.read()
        return HTMLResponse(content=html_content, status_code=200)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read HTML report for apk_id '{apk_id}': {str(exc)}",
        )
