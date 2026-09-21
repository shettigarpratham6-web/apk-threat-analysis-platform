"""FastAPI application entry point."""

from fastapi import FastAPI
from backend.app.routes.static_analysis import router as static_analysis_router
from backend.app.routes.dynamic_analysis import router as dynamic_analysis_router

app = FastAPI(title="APK Threat Analysis Platform")

app.include_router(static_analysis_router, prefix="/api/static-analysis", tags=["Static Analysis"])
app.include_router(dynamic_analysis_router, prefix="/api/dynamic-analysis", tags=["Dynamic Analysis"])


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


