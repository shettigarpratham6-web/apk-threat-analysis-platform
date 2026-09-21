from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.routes.static_analysis import router as static_analysis_router
from backend.app.routes.dynamic_analysis import router as dynamic_analysis_router
from backend.app.routes.correlation import router as correlation_router
from backend.app.routes.reporting import router as reporting_router

app = FastAPI(title="APK Threat Analysis Platform")

# Enable CORS for browser frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


app.include_router(static_analysis_router, prefix="/api/static-analysis", tags=["Static Analysis"])
app.include_router(dynamic_analysis_router, prefix="/api/dynamic-analysis", tags=["Dynamic Analysis"])
app.include_router(correlation_router, prefix="/api/correlation", tags=["Correlation & Risk Scoring"])
app.include_router(reporting_router, prefix="/api/report", tags=["Forensic Reporting"])


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}





