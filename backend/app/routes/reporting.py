"""FastAPI router for generating, downloading, and viewing forensic analysis reports."""

import logging
import os
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, status, Query
from fastapi.responses import FileResponse, HTMLResponse

from backend.app.reporting.report_generator import generate_report

router = APIRouter()
logger = logging.getLogger("reporting_routes")

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


@router.post("/generate/{apk_id}")
async def generate_forensic_report(apk_id: str):
    """
    Generates PDF, HTML, and JSON forensic report artifacts for the given apk_id.
    """
    try:
        urls = generate_report(apk_id)
        return urls
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=404, detail=str(fnf))
    except Exception as err:
        logger.error(f"Error generating forensic report for apk_id '{apk_id}': {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while generating forensic report: {str(err)}",
        )


@router.get("/download/{apk_id}")
async def download_report(apk_id: str, format: str = Query("pdf")):
    """
    Downloads the compiled PDF or JSON forensic report file.
    """
    if format == "json":
        file_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.json")
        media_type = "application/json"
        filename = f"{apk_id}_report.json"
    elif format == "csv":
        file_path = os.path.join(RESULTS_DIR, f"{apk_id}_ioc.csv")
        media_type = "text/csv"
        filename = f"{apk_id}_ioc.csv"
    elif format == "ioc":
        file_path = os.path.join(RESULTS_DIR, f"{apk_id}_ioc.json")
        media_type = "application/json"
        filename = f"{apk_id}_ioc.json"
    else:
        file_path = os.path.join(RESULTS_DIR, f"{apk_id}_report.pdf")
        media_type = "application/pdf"
        filename = f"{apk_id}_report.pdf"

    if not os.path.exists(file_path):
        # Try generating report if not present
        try:
            generate_report(apk_id)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report file not found and generation failed: {str(exc)}",
            )

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file could not be generated.")

    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=filename,
    )


@router.get("/view/{apk_id}")
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
                detail=f"HTML report not found and generation failed: {str(exc)}",
            )

    try:
        with open(html_path, "r", encoding="utf-8") as hf:
            html_content = hf.read()
        return HTMLResponse(content=html_content, status_code=200)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
