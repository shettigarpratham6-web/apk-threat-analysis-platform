"""FastAPI router for correlation and risk scoring endpoints."""

import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, status

from backend.app.correlation.aggregator import correlate_apk
from backend.app.security import validate_apk_id

router = APIRouter()
logger = logging.getLogger("correlation_routes")

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


@router.post("/analyze")
async def analyze_correlation(
    apk_id: Optional[str] = Form(None),
):
    if not apk_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'apk_id' is required.",
        )

    apk_id = validate_apk_id(apk_id)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    try:
        correlation_result = correlate_apk(apk_id)

        correlation_file_path = os.path.join(RESULTS_DIR, f"{apk_id}_correlation.json")
        with open(correlation_file_path, "w", encoding="utf-8") as cf:
            json.dump(correlation_result, cf, indent=2)

        return correlation_result
    except Exception as err:
        logger.error(f"Error executing correlation analysis for apk_id '{apk_id}': {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during correlation analysis.",
        )
