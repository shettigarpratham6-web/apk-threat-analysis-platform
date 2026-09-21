# APK Threat Analysis Platform

A workspace scaffold for analyzing Android APKs through static analysis, dynamic sandboxing, C2 detection, evidence correlation, and forensic reporting.

## Structure

- `frontend/` — React web interface
- `backend/` — FastAPI service and analysis pipeline
- `sandbox/` — Android emulator, Frida, and mitmproxy configuration
- `yara_rules/` — malware detection rules
- `datasets/` — authorized test APK datasets
- `tests/` — unit and integration test placeholders
- `docs/` — project documentation
- `docker/` — container setup

## Configuration

Set the required API keys in a local `.env` file. Never commit real credentials.

This repository currently contains the requested project structure and placeholders; analysis implementations can be added incrementally.
