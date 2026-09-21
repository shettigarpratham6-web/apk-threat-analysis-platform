"""FastAPI application entry point."""

from fastapi import FastAPI

app = FastAPI(title="APK Threat Analysis Platform")


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
