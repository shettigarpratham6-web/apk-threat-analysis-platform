"""FastAPI router for dynamic analysis sandbox lifecycle, APK execution, and behavior monitoring endpoints."""

import json
import logging
import os
import shutil
import uuid
from typing import Optional
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from backend.app.dynamic_analysis.sandbox_manager import SandboxManager

router = APIRouter()
logger = logging.getLogger("dynamic_analysis_routes")

# Module-level singleton instance for sandbox manager
sandbox = SandboxManager()

# Resolve paths to backend/uploads and backend/results directories
UPLOADS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "uploads"))
RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


@router.post("/sandbox/start")
async def start_sandbox():
    """
    Launches the Android emulator sandbox process and waits for ADB device readiness.
    """
    try:
        sandbox.start_emulator()
        sandbox.wait_until_ready()
        return {
            "status": "ready",
            "avd_name": sandbox.avd_name,
            "headless": sandbox.headless,
        }
    except TimeoutError as te:
        logger.error(f"Sandbox launch timed out: {te}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(te),
        )
    except RuntimeError as re:
        logger.error(f"Sandbox runtime error: {re}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(re),
        )
    except Exception as err:
        logger.error(f"Unexpected error starting sandbox: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to launch sandbox emulator: {str(err)}",
        )


@router.post("/sandbox/stop")
async def stop_sandbox():
    """
    Terminates the Android emulator sandbox process cleanly.
    """
    try:
        sandbox.stop_emulator()
        return {"status": "stopped"}
    except Exception as err:
        logger.error(f"Sandbox stop failure: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop sandbox emulator: {str(err)}",
        )


@router.post("/run")
async def run_apk_safely(
    apk_id: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """
    Installs and launches the target APK inside the running sandbox emulator.
    Accepts either an apk_id (referencing a saved APK in backend/uploads/) or a direct APK upload.
    """
    resolved_apk_id = apk_id
    file_path = None

    os.makedirs(UPLOADS_DIR, exist_ok=True)

    if file is not None and file.filename and file.filename.lower().endswith(".apk"):
        if not resolved_apk_id:
            resolved_apk_id = str(uuid.uuid4())
        file_path = os.path.join(UPLOADS_DIR, f"{resolved_apk_id}.apk")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    elif resolved_apk_id:
        target_path = os.path.join(UPLOADS_DIR, f"{resolved_apk_id}.apk")
        if os.path.exists(target_path):
            file_path = target_path
        else:
            matching_files = [
                os.path.join(UPLOADS_DIR, f)
                for f in os.listdir(UPLOADS_DIR)
                if resolved_apk_id in f and f.endswith(".apk")
            ]
            if matching_files:
                file_path = matching_files[0]

    if not file_path or not os.path.exists(file_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="APK file not found. Provide a valid 'apk_id' of an uploaded file or attach a new '.apk' file.",
        )

    try:
        result = sandbox.run_full_dynamic_prep(file_path)
        return {
            "apk_id": resolved_apk_id,
            "package_name": result["package_name"],
            "status": result["status"],
        }
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )
    except RuntimeError as run_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(run_err),
        )
    except Exception as err:
        logger.error(f"Error launching APK in sandbox: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while launching APK in sandbox: {str(err)}",
        )


@router.post("/monitor")
async def monitor_apk_behavior(
    apk_id: str = Form(...),
    package_name: Optional[str] = Form(None),
    duration: int = Form(30),
):
    """
    Monitors network traffic (mitmproxy), file activity, and API calls (Frida) while
    the APK is running live in the sandbox. Saves result JSON to backend/results/<apk_id>_dynamic.json.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    resolved_package_name = package_name

    if not resolved_package_name:
        apk_path = os.path.join(UPLOADS_DIR, f"{apk_id}.apk")
        if not os.path.exists(apk_path) and os.path.exists(UPLOADS_DIR):
            matching_files = [
                os.path.join(UPLOADS_DIR, f)
                for f in os.listdir(UPLOADS_DIR)
                if apk_id in f and f.endswith(".apk")
            ]
            if matching_files:
                apk_path = matching_files[0]

        if os.path.exists(apk_path):
            from backend.app.dynamic_analysis.apk_runner import ApkRunner

            runner = ApkRunner(adb_path=sandbox.adb_path)
            try:
                resolved_package_name = runner.get_package_name(apk_path)
            except Exception as exc:
                logger.warning(f"Could not extract package name for apk_id {apk_id}: {exc}")

    if not resolved_package_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Package name could not be resolved. Please specify 'package_name' or ensure APK exists in uploads.",
        )

    try:
        behavior_results = sandbox.monitor_behavior(
            package_name=resolved_package_name,
            apk_id=apk_id,
            duration=duration,
        )

        response_payload = {
            "apk_id": apk_id,
            "package_name": resolved_package_name,
            "dynamic_analysis": behavior_results,
        }

        # Persist dynamic analysis result to backend/results/<apk_id>_dynamic.json
        result_file_path = os.path.join(RESULTS_DIR, f"{apk_id}_dynamic.json")
        with open(result_file_path, "w", encoding="utf-8") as rf:
            json.dump(response_payload, rf, indent=2)

        return response_payload
    except Exception as err:
        logger.error(f"Error monitoring behavior for apk_id '{apk_id}': {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during behavior monitoring: {str(err)}",
        )


class C2DetectRequest(BaseModel if 'BaseModel' in globals() else object):
    pass


@router.post("/c2-detect")
async def detect_c2_endpoint(
    apk_id: Optional[str] = Form(None),
):
    """
    Analyzes captured dynamic network traffic (and optional static code analysis indicators)
    to flag likely Command & Control (C2) communication.
    Saves result to backend/results/<apk_id>_c2.json and returns the detection payload.
    """
    if not apk_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'apk_id' is required.",
        )

    dynamic_file = os.path.join(RESULTS_DIR, f"{apk_id}_dynamic.json")
    if not os.path.exists(dynamic_file):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dynamic analysis results for apk_id '{apk_id}' not found. Run dynamic monitoring first.",
        )

    try:
        with open(dynamic_file, "r", encoding="utf-8") as df:
            dynamic_results = json.load(df)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read dynamic results for apk_id '{apk_id}': {str(exc)}",
        )

    static_results = None
    static_file = os.path.join(RESULTS_DIR, f"{apk_id}_static.json")
    if os.path.exists(static_file):
        try:
            with open(static_file, "r", encoding="utf-8") as sf:
                static_results = json.load(sf)
        except Exception as exc:
            logger.warning(f"Could not parse static results file '{static_file}': {exc}")

    try:
        c2_result = sandbox.run_c2_detection(dynamic_results, static_results)

        payload = {
            "apk_id": apk_id,
            "suspected_c2_hosts": c2_result.get("suspected_c2_hosts", []),
            "raw_flagged_traffic": c2_result.get("raw_flagged_traffic", []),
            "c2_detection": c2_result,
        }

        # Save result to backend/results/<apk_id>_c2.json
        c2_file_path = os.path.join(RESULTS_DIR, f"{apk_id}_c2.json")
        with open(c2_file_path, "w", encoding="utf-8") as cf:
            json.dump(payload, cf, indent=2)

        return payload
    except Exception as err:
        logger.error(f"Error running C2 detection for apk_id '{apk_id}': {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during C2 detection: {str(err)}",
        )


@router.post("/check-servers")
async def check_servers_endpoint(
    apk_id: Optional[str] = Form(None),
):
    """
    Checks flagged C2 domains and IP addresses against external reputation sources (AbuseIPDB, VirusTotal).
    Saves results to backend/results/<apk_id>_servers.json and returns verdict summary.
    """
    if not apk_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'apk_id' is required.",
        )

    c2_file = os.path.join(RESULTS_DIR, f"{apk_id}_c2.json")
    if not os.path.exists(c2_file):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"C2 detection results for apk_id '{apk_id}' not found. Run C2 detection first.",
        )

    try:
        with open(c2_file, "r", encoding="utf-8") as cf:
            c2_results = json.load(cf)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read C2 results for apk_id '{apk_id}': {str(exc)}",
        )

    suspected_hosts = c2_results.get("suspected_c2_hosts", [])
    if not suspected_hosts and "c2_detection" in c2_results and isinstance(c2_results["c2_detection"], dict):
        suspected_hosts = c2_results["c2_detection"].get("suspected_c2_hosts", [])

    try:
        from backend.app.dynamic_analysis.server_reputation import check_all

        reputation_results = check_all(suspected_hosts)

        payload = {
            "apk_id": apk_id,
            "checked": reputation_results.get("checked", []),
            "server_reputation": reputation_results,
        }

        # Save result to backend/results/<apk_id>_servers.json
        servers_file_path = os.path.join(RESULTS_DIR, f"{apk_id}_servers.json")
        with open(servers_file_path, "w", encoding="utf-8") as sf:
            json.dump(payload, sf, indent=2)

        return payload
    except Exception as err:
        logger.error(f"Error checking server reputation for apk_id '{apk_id}': {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during suspicious server lookup: {str(err)}",
        )


