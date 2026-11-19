# APK Threat Analysis Platform

The APK Threat Analysis Platform is an automated Android application security analysis pipeline that combines static code inspection, dynamic emulator sandboxing, and Command and Control (C2) detection. The system decompiles bytecode using JADX, extracts feature vectors for Random Forest and CodeBERT analyzers, executes applications inside an Android emulator with Frida hooks and mitmproxy traffic capture, and aggregates evidence into a unified risk score. It is designed for security analysts and reverse engineers inspecting untrusted APK packages within an isolated testing environment.

## Directory Layout

- `backend/app/`: FastAPI backend service, REST routing, and analysis engines.
- `frontend/src/`: React and Vite user interface.
- `sandbox/`: Emulator lifecycle management, network traffic capture, and Frida scripts.
- `yara_rules/`: Malware signature rules for permissions, suspicious APIs, and known threats.
- `ml/`: Trained Random Forest model, feature index definitions, and SHA-256 integrity checksum.
- `tools/`: Tool download script and external Android utilities.
- `docker/`: Docker Compose configuration and container definitions.
- `tests/`: Automated backend test suite.

## Implementation Status

| Feature | Status | Notes |
| :--- | :--- | :--- |
| Static Analysis | Implemented | Manifest parsing, DEX decompilation, YARA signatures, Random Forest classifier, and CodeBERT similarity. |
| Dynamic Analysis | Implemented | Emulator lifecycle, APK installation, automated UI exercise, Frida hooks, and mitmproxy capture. |
| C2 Detection | Implemented | Periodic beaconing interval analysis, DNS Shannon entropy, and suspicious destination IP verification. |
| Threat Intelligence | Partial | VirusTotal lookup enabled when VIRUSTOTAL_API_KEY is configured. |
| LLM Narrative | Partial | Optional Gemini or OpenAI threat narrative enabled when LLM_ENABLED is true. |
| Forensic Reporting | Implemented | HTML and PDF export with risk score breakdown and IOC extraction. |
| Live Screen Mirroring | Not Working | Simulated mock frames only; real device streaming requires scrcpy or WebRTC integration. |

## Prerequisites

- Python 3.11 or later
- Node.js 20 or later
- Android SDK with platform-tools (adb) and emulator
- Java Development Kit (JDK) 11 or later (required for JADX and Apktool)
- mitmproxy (optional, required for dynamic HTTP/HTTPS network interception)

## Quick Start

### 1. Download Tool Binaries
```bash
bash tools/fetch_tools.sh
```

### 2. Backend Setup
```bash
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env
uvicorn backend.main:app --reload
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### 4. Docker Setup
```bash
docker compose -f docker/docker-compose.yml up --build
```
Note: Dynamic sandbox analysis requires an Android emulator running on the host system.

## Security

- API key authentication: Disabled by default in development mode. Set `ENV=production` and configure `API_KEY` to enforce the `X-API-Key` header on all `/api/*` endpoints.
- Localhost binding: Development servers bind to `127.0.0.1` by default. Do not expose services directly to public networks without an authenticating reverse proxy.
- Reports: Content Security Policy and X-Content-Type-Options nosniff headers prevent stored cross-site scripting in HTML reports. User-supplied text values are XML-escaped in PDF reports.
- Uploads: Uploads are streamed with a 200 MB maximum size limit. Archive extraction enforces path checks against directory traversal (zip-slip).
- Untrusted APK data: Manifest values, extracted package names, and raw strings are treated as untrusted input and enclosed in delimiters before passing to analyzers.

## Disclaimer

This software is intended solely for authorized security research, vulnerability analysis, and educational purposes on applications that the user owns or has explicit permission to test. Unauthorized reverse engineering, interception, or analysis of third-party software may violate applicable laws and terms of service.
