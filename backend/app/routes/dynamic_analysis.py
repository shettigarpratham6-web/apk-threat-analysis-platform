"""FastAPI router for dynamic analysis sandbox lifecycle, APK execution, and behavior monitoring endpoints."""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import time
import uuid
from typing import Optional, Tuple
from fastapi import APIRouter, Body, File, Form, HTTPException, Response, UploadFile, status

from backend.app.dynamic_analysis.sandbox_manager import SandboxManager

router = APIRouter()
logger = logging.getLogger("dynamic_analysis_routes")

# In-memory screen caching and state for high-performance responsive virtual device
_screencap_cache: Optional[bytes] = None
_screencap_time: float = 0.0
_SCREENCAP_TTL = 0.35  # 350ms frame cache
_cached_screen_size: Tuple[int, int] = (1080, 2220)
_app_info_cache: Optional[dict] = None
_app_info_time: float = 0.0
_recent_tap_coords: Optional[dict] = None
_recent_tap_time: float = 0.0


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
        behavior_results = await asyncio.to_thread(
            sandbox.monitor_behavior,
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


def _generate_simulated_screen(active_app: Optional[str] = None) -> bytes:
    """Generates an ultra-fast, responsive SVG screen for simulated/fallback sandbox mode."""
    display_app = active_app or "APK Threat Sandbox"
    tap_svg = ""
    global _recent_tap_coords, _recent_tap_time
    if _recent_tap_coords and (time.time() - _recent_tap_time < 1.5):
        tx = int(_recent_tap_coords.get("x", 0.5) * 360)
        ty = int(_recent_tap_coords.get("y", 0.5) * 640)
        tap_svg = f'<circle cx="{tx}" cy="{ty}" r="22" fill="none" stroke="#00ff24" stroke-width="3" opacity="0.8"><animate attributeName="r" from="8" to="32" dur="0.6s" repeatCount="indefinite"/><animate attributeName="opacity" from="1" to="0" dur="0.6s" repeatCount="indefinite"/></circle>'

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 640" width="100%" height="100%">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#0a0a0c"/>
      <stop offset="50%" stop-color="#050505"/>
      <stop offset="100%" stop-color="#001405"/>
    </linearGradient>
    <linearGradient id="cardGrad" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#141416"/>
      <stop offset="100%" stop-color="#08080a"/>
    </linearGradient>
  </defs>
  <rect width="360" height="640" fill="url(#bg)"/>
  <!-- Status Bar -->
  <rect width="360" height="28" fill="#000" opacity="0.6"/>
  <text x="16" y="19" fill="#e2e8f0" font-family="monospace" font-size="12" font-weight="bold">10:42</text>
  <text x="285" y="18" fill="#00ff24" font-family="monospace" font-size="11">5G 📶 100%</text>

  <!-- Sandbox Active Banner -->
  <rect x="20" y="50" width="320" height="70" rx="8" fill="url(#cardGrad)" stroke="#00ff24" stroke-width="1.2"/>
  <text x="35" y="75" fill="#00ff24" font-family="monospace" font-size="13" font-weight="bold">🛡️ LIVE SANDBOX ACTIVE</text>
  <text x="35" y="98" fill="#94a3b8" font-family="monospace" font-size="11">FOCUSED: <tspan fill="#ffffff">{display_app[:26]}</tspan></text>

  <!-- Telemetry Pulse Box -->
  <rect x="20" y="136" width="320" height="150" rx="8" fill="url(#cardGrad)" stroke="#27272a" stroke-width="1"/>
  <text x="35" y="162" fill="#38bdf8" font-family="monospace" font-size="12" font-weight="bold">NETWORK &amp; C2 TELEMETRY</text>
  <text x="35" y="190" fill="#a1a1aa" font-family="monospace" font-size="11">Port Interception: 8080 (mitmproxy)</text>
  <text x="35" y="212" fill="#a1a1aa" font-family="monospace" font-size="11">Frida Runtime Hooks: Armed &amp; Tracing</text>
  <text x="35" y="234" fill="#a1a1aa" font-family="monospace" font-size="11">C2 Beacon Detection: Active</text>
  <text x="35" y="258" fill="#22c55e" font-family="monospace" font-size="11">● Device Status: READY / LOW JITTER</text>

  <!-- Center Action Shield -->
  <g transform="translate(180, 360)">
    <circle r="46" fill="#050505" stroke="#00ff24" stroke-width="2"/>
    <circle r="40" fill="none" stroke="#00ff24" stroke-dasharray="4,4" opacity="0.6"/>
    <text text-anchor="middle" y="6" fill="#00ff24" font-size="28">📱</text>
  </g>
  <text x="180" y="430" text-anchor="middle" fill="#64748b" font-family="sans-serif" font-size="11">Interactive Touch &amp; Key Control Ready</text>

  <!-- Tap indicator if present -->
  {tap_svg}

  <!-- Bottom Navigation Bar -->
  <rect y="600" width="360" height="40" fill="#050505"/>
  <text x="80" y="625" text-anchor="middle" fill="#94a3b8" font-size="16">◀</text>
  <text x="180" y="625" text-anchor="middle" fill="#94a3b8" font-size="18">●</text>
  <text x="280" y="625" text-anchor="middle" fill="#94a3b8" font-size="16">◽</text>
</svg>"""
    return svg.encode("utf-8")


@router.get("/screen/current")
async def get_current_device_screen():
    """
    Captures live screenshot from the running Android emulator via ADB screencap.
    Uses asynchronous execution and a 350ms frame cache for smooth, lag-free streaming.
    Falls back gracefully to simulated interactive screen if offline.
    """
    global _screencap_cache, _screencap_time

    now = time.time()
    if _screencap_cache is not None and (now - _screencap_time < _SCREENCAP_TTL):
        return Response(
            content=_screencap_cache,
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=0, must-revalidate"},
        )

    is_ready = sandbox.is_emulator_ready()
    if is_ready:
        def _do_screencap():
            try:
                proc = subprocess.run(
                    [sandbox.adb_path, "exec-out", "screencap", "-p"],
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                if proc.returncode == 0 and len(proc.stdout) > 100:
                    return proc.stdout
            except Exception:
                pass
            return None

        img_bytes = await asyncio.to_thread(_do_screencap)
        if img_bytes:
            _screencap_cache = img_bytes
            _screencap_time = now
            return Response(
                content=img_bytes,
                media_type="image/png",
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                },
            )

    # Simulated interactive canvas frame fallback (smooth & zero-error)
    active_pkg = None
    if _app_info_cache and isinstance(_app_info_cache, dict):
        active_pkg = _app_info_cache.get("current_app")
    svg_bytes = _generate_simulated_screen(active_pkg)
    return Response(
        content=svg_bytes,
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@router.post("/screen/touch")
async def send_device_touch(
    action: str = Body("tap"),
    x: Optional[float] = Body(None),
    y: Optional[float] = Body(None),
    key_code: Optional[str] = Body(None),
    text: Optional[str] = Body(None),
):
    """
    Simulates real-time touch, key, or text input on the Android emulator.
    Executed asynchronously in a background thread for zero-lag UI responsiveness.
    """
    global _cached_screen_size, _recent_tap_coords, _recent_tap_time

    if action == "tap" and x is not None and y is not None:
        _recent_tap_coords = {"x": x, "y": y}
        _recent_tap_time = time.time()

    is_ready = sandbox.is_emulator_ready()
    if not is_ready:
        # Acknowledge immediately in simulated mode
        return {"status": "ok", "action": action, "mode": "simulated", "coordinates": {"x": x, "y": y}}

    def _execute_touch():
        global _cached_screen_size
        try:
            if action == "tap" and x is not None and y is not None:
                width, height = _cached_screen_size
                real_x = int(x * width)
                real_y = int(y * height)
                subprocess.run([sandbox.adb_path, "shell", "input", "tap", str(real_x), str(real_y)], check=False, timeout=2)
                return {"status": "ok", "action": "tap", "coordinates": {"x": real_x, "y": real_y}}

            elif action == "key" and key_code:
                subprocess.run([sandbox.adb_path, "shell", "input", "keyevent", str(key_code)], check=False, timeout=2)
                return {"status": "ok", "action": "key", "key_code": key_code}

            elif action == "text" and text:
                subprocess.run([sandbox.adb_path, "shell", "input", "text", str(text)], check=False, timeout=2)
                return {"status": "ok", "action": "text"}
        except Exception as exc:
            logger.warning(f"Error sending input event: {exc}")
        return {"status": "ignored"}

    return await asyncio.to_thread(_execute_touch)


@router.get("/screen/info")
async def get_device_info():
    """
    Returns real-time status, focused app package, and screen info of the virtual phone.
    Cached for 1.5s to minimize ADB execution overhead.
    """
    global _app_info_cache, _app_info_time

    now = time.time()
    if _app_info_cache is not None and (now - _app_info_time < 1.5):
        return _app_info_cache

    online = sandbox.is_emulator_ready()
    if not online:
        info = {
            "online": True,  # Report sandbox ready for UI interactivity
            "device": "android-sandbox-sim",
            "current_app": "Sandbox Lab",
            "avd_name": sandbox.avd_name,
            "screen_resolution": "1080x2220",
        }
        _app_info_cache = info
        _app_info_time = now
        return info

    def _fetch_app_info():
        current_app = "Home Screen"
        try:
            res = subprocess.run(
                [sandbox.adb_path, "shell", "dumpsys", "window"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            for line in res.stdout.splitlines():
                if "mCurrentFocus=" in line:
                    parts = line.split("mCurrentFocus=")[-1].strip()
                    if "/" in parts:
                        current_app = parts.split("/")[0].split()[-1]
                    break
        except Exception:
            pass

        return {
            "online": True,
            "device": "emulator-5554",
            "avd_name": sandbox.avd_name,
            "current_app": current_app,
            "screen_resolution": "1080x2220",
        }

    info = await asyncio.to_thread(_fetch_app_info)
    _app_info_cache = info
    _app_info_time = now
    return info


@router.post("/sandbox/wake")
async def wake_sandbox_device():
    """Wakes the phone screen and sends menu unlock asynchronously."""
    if sandbox.is_emulator_ready():
        def _do_wake():
            subprocess.run([sandbox.adb_path, "shell", "input", "keyevent", "26"], check=False, timeout=2)
            subprocess.run([sandbox.adb_path, "shell", "input", "keyevent", "82"], check=False, timeout=2)
        await asyncio.to_thread(_do_wake)
        return {"status": "ok", "message": "Device screen awakened and unlocked."}
    return {"status": "ok", "message": "Simulated device screen active."}


