# Docker Deployment & Execution Guide

This guide explains how to launch the **APK Threat Analysis Platform** using Docker Compose for poster presentation day.

---

## 🏗️ Architecture Overview

The system consists of two Dockerized web services and one host-native execution stage:

1. **`backend` (Port 8000):** FastAPI REST API, Androguard static parser, YARA rule scanner, C2 detection engine, and WeasyPrint PDF report generator.
2. **`frontend` (Port 5173):** React + Vite interactive dashboard, stage stepper, risk score visualization, and PDF report viewer.
3. **`host-native sandbox` (Host Machine):** Android Emulator AVD (`threat_sandbox_avd`), Frida RPC server, and `mitmproxy` traffic interceptor.

> ⚠️ **Important Demo Architecture Note:**  
> The Android Emulator and hardware acceleration (KVM/HAXM) run on the **host machine**, while the Web Dashboard and Analysis Backend run in Docker containers.

---

## 🚀 Quickstart Commands

### Step 1: Prepare Environment Variables
Copy `.env.example` to `.env` in the root directory:
```bash
cp .env.example .env
```
Ensure optional API keys (e.g. `VT_API_KEY`, `ABUSEIPDB_API_KEY`) are set if live threat intelligence enrichment is desired.

### Step 2: Start Host-Level Sandbox Emulator
Before executing dynamic sandbox stages, launch your pre-configured AVD on the host machine:
```bash
emulator -avd threat_sandbox_avd -no-snapshot-save
```
Verify device readiness via ADB:
```bash
adb devices
```

### Step 3: Launch Dockerized Stack
From the project root directory, run:
```bash
docker compose -f docker/docker-compose.yml up --build
```

Access the platform interfaces in your web browser:
- **Web Dashboard:** [http://localhost:5173](http://localhost:5173)
- **Backend API Docs & Health:** [http://localhost:8000/docs](http://localhost:8000/docs) | [http://localhost:8000/health](http://localhost:8000/health)

---

## 🧪 Pre-Demo Smoke Test
To verify all 7 pipeline stages end-to-end before your presentation, execute the automated dry-run smoke test script:
```bash
python backend/scripts/demo_smoke_test.py
```
This script runs the full pipeline on `datasets/benign/sample.apk`, prints pass/fail per stage, and outputs the final calculated risk score.
