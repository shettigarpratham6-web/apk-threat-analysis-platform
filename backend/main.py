from contextlib import asynccontextmanager
from dotenv import load_dotenv
load_dotenv()

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.routes.static_analysis import router as static_analysis_router
from backend.app.routes.dynamic_analysis import router as dynamic_analysis_router
from backend.app.routes.correlation import router as correlation_router
from backend.app.routes.reporting import router as reporting_router
from backend.app.routes.auth import router as auth_router, get_current_user
from backend.config import AUTH_PROTECT_API
from backend.database.database import Base, engine
import backend.database.models  # noqa: F401  (registers tables on Base.metadata)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-warm static analysis caches, ML models, and YARA rules to eliminate cold-start latency."""
    import asyncio
    import logging

    startup_logger = logging.getLogger("startup_warmup")

    # Create the users table on first run (SQLite file at backend/data/app.db by default).
    Base.metadata.create_all(bind=engine)

    def _warm():
        try:
            from backend.app.static_analysis.signature_check import get_compiled_rules
            get_compiled_rules()
            startup_logger.info("YARA rules pre-compiled and cached successfully.")
        except Exception as exc:
            startup_logger.debug(f"YARA pre-compile note: {exc}")

        try:
            from backend.core.static_analysis.ml_classifier import get_static_malware_classifier
            clf = get_static_malware_classifier()
            if clf.is_ready():
                startup_logger.info("Static malware classifier pre-warmed successfully.")
        except Exception as exc:
            startup_logger.debug(f"ML pre-warm note: {exc}")

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _warm)
    yield


app = FastAPI(title="APK Threat Analysis Platform", lifespan=lifespan)

# Enable CORS for local browser frontend communication (Hardened against CSRF)
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global error handler ensuring all exceptions return clean JSON error payloads."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "message": str(exc) or "An internal server error occurred.",
            "path": str(request.url.path),
        },
    )


# When AUTH_PROTECT_API is true (default) every analysis endpoint requires a valid session.
_protected = [Depends(get_current_user)] if AUTH_PROTECT_API else []

app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(static_analysis_router, prefix="/api/static-analysis", tags=["Static Analysis"], dependencies=_protected)
app.include_router(dynamic_analysis_router, prefix="/api/dynamic-analysis", tags=["Dynamic Analysis"], dependencies=_protected)
app.include_router(correlation_router, prefix="/api/correlation", tags=["Correlation & Risk Scoring"], dependencies=_protected)
app.include_router(reporting_router, prefix="/api/report", tags=["Forensic Reporting"], dependencies=_protected)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}





