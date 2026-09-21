"""FastAPI router for dynamic analysis sandbox lifecycle endpoints."""

import logging
from fastapi import APIRouter, HTTPException, status

from backend.app.dynamic_analysis.sandbox_manager import SandboxManager

router = APIRouter()
logger = logging.getLogger("dynamic_analysis_routes")

# Module-level singleton instance for sandbox manager
sandbox = SandboxManager()


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
