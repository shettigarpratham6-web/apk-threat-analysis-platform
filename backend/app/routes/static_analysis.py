"""FastAPI router for static analysis endpoints."""

import json
import os
import shutil
import uuid
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.static_analysis.apk_loader import extract_apk
from backend.app.static_analysis.manifest_check import analyze_manifest
from backend.app.static_analysis.code_analysis import analyze_code
from backend.app.static_analysis.signature_check import run_yara_scan, check_virustotal
from backend.app.static_analysis.aggregator import run_static_analysis

router = APIRouter()

# Resolve paths for backend/uploads and backend/results directories
UPLOADS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "uploads"))
RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


def save_temp_apk(file: UploadFile) -> str:
    """
    Saves an uploaded APK file temporarily to the uploads directory.

    :param file: Uploaded file object from FastAPI endpoint.
    :return: Absolute file path to the saved temporary APK.
    :raises HTTPException: If the file is not a valid .apk file.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Please upload a valid .apk file.",
        )

    os.makedirs(UPLOADS_DIR, exist_ok=True)
    temp_filename = f"{uuid.uuid4()}.apk"
    file_path = os.path.join(UPLOADS_DIR, temp_filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return file_path


@router.post("/analyze")
async def analyze_apk_pipeline(file: UploadFile = File(...)):
    """
    Unified Static Analysis Endpoint.
    Accepts an uploaded APK file, executes complete static analysis (manifest, code scan,
    YARA signatures, VirusTotal lookup), computes static risk indicators, persists results
    to backend/results/<apk_id>_static.json, and returns combined JSON response.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Please upload a valid .apk file.",
        )

    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    apk_id = str(uuid.uuid4())
    temp_filename = f"{apk_id}.apk"
    file_path = os.path.join(UPLOADS_DIR, temp_filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        static_results = run_static_analysis(file_path)

        payload = {
            "apk_id": apk_id,
            "static_analysis": static_results,
        }

        # Persist JSON result to backend/results/<apk_id>_static.json
        result_file_path = os.path.join(RESULTS_DIR, f"{apk_id}_static.json")
        with open(result_file_path, "w", encoding="utf-8") as rf:
            json.dump(payload, rf, indent=2)

        return payload
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during static analysis: {str(err)}",
        )
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass


@router.post("/upload")
async def upload_and_analyze_apk(file: UploadFile = File(...)):
    """
    Accepts an uploaded APK file, extracts manifest permissions and package metadata,
    and returns the manifest analysis results as JSON.
    """
    file_path = save_temp_apk(file)
    try:
        apk = extract_apk(file_path)
        manifest_result = analyze_manifest(apk)
        return manifest_result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while analyzing the APK manifest: {str(err)}",
        )
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass


@router.post("/code-scan")
async def scan_apk_code(file: UploadFile = File(...)):
    """
    Accepts an uploaded APK file, performs static bytecode analysis to extract URLs,
    IPv4 addresses, and suspicious API invocations, and returns the result as JSON.
    """
    file_path = save_temp_apk(file)
    try:
        code_result = analyze_code(file_path)
        return code_result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during code analysis: {str(err)}",
        )
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass


@router.post("/signature-check")
async def check_apk_signatures(file: UploadFile = File(...)):
    """
    Accepts an uploaded APK file, runs local YARA signature scanning and
    optional VirusTotal hash lookup, and returns combined JSON results.
    """
    file_path = save_temp_apk(file)
    try:
        yara_matches = run_yara_scan(file_path)
        vt_result = check_virustotal(file_path)
        return {
            "yara_matches": yara_matches,
            "virustotal": vt_result,
        }
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during signature check: {str(err)}",
        )
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
