import os
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from backend.app.routes.correlation import router as correlation_router
from backend.app.routes.dynamic_analysis import router as dynamic_analysis_router
from backend.app.routes.reporting import router as reporting_router
from backend.app.routes.static_analysis import router as static_analysis_router
from backend.app.security import require_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("ENV") == "production" and not os.getenv("API_KEY"):
        raise RuntimeError("API_KEY must be set in production environment")

    uploads_dir = Path(__file__).resolve().parent / "uploads"
    if uploads_dir.exists():
        now = time.time()
        for item in uploads_dir.iterdir():
            if item.is_dir():
                try:
                    if item.stat().st_mtime < now - 3600:
                        shutil.rmtree(item, ignore_errors=True)
                except Exception as e:
                    logger.warning(f"Failed to cleanup stale upload {item}: {e}")
    yield


app = FastAPI(title="APK Threat Analysis Platform", lifespan=lifespan)

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled error on {request.url.path}")
    return JSONResponse(status_code=500, content={"status": "error", "message": "Internal server error."})


app.include_router(
    static_analysis_router,
    prefix="/api/static-analysis",
    tags=["Static Analysis"],
    dependencies=[Depends(require_api_key)],
)
app.include_router(
    dynamic_analysis_router,
    prefix="/api/dynamic-analysis",
    tags=["Dynamic Analysis"],
    dependencies=[Depends(require_api_key)],
)
app.include_router(
    correlation_router,
    prefix="/api/correlation",
    tags=["Correlation & Risk Scoring"],
    dependencies=[Depends(require_api_key)],
)
app.include_router(
    reporting_router,
    prefix="/api/report",
    tags=["Forensic Reporting"],
    dependencies=[Depends(require_api_key)],
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
