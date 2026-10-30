# APK Threat Analysis Platform — Final Implementation Report

## Overview
This document summarizes the comprehensive stabilization and enhancement sprint conducted to transform the existing repository into a production-ready Static APK Threat Analysis Platform. The platform successfully accepts an APK, unzips it securely, analyzes it for threats across 10 different stages, aggregates the findings into an IOC (Indicators of Compromise) dataset, and generates professional-grade cyber-forensic reports in HTML, JSON, CSV, and PDF formats.

## 1. Bugs Fixed & Enhancements
- **Import Errors:** Fixed all unresolved module paths across the application. `backend` root must be the execution context.
- **Dependency Issues:** Installed missing core packages (`loguru`, `fastapi`, `uvicorn`, `pydantic`, `reportlab`, `jinja2`).
- **Resiliency / Error Handling:** Refactored `/api/static-analysis/analyze` to use a robust wrapper for each analysis module. If one module (like YARA or Code Analysis) crashes, it fails gracefully without terminating the pipeline.
- **Resource Cleanup:** Ensure `extract_dir` and the original uploaded `.apk` are cleanly removed via a `finally` block to prevent disk exhaustion.
- **Reporting Generator Integration:** Resolved template linking for HTML generation and ensured `PDF`/`JSON`/`CSV` delivery via the download API endpoints.

## 2. Advanced Security Scanning Introduced
### a) JADX & APKTool Hybrid Engine
- Implemented a timeout wrapper (120 seconds) on `jadx`.
- If `jadx` fails (due to heavy obfuscation), the engine seamlessly falls back to `apktool d` to extract `.smali` files, ensuring static analysis continues unhindered.

### b) String Entropy & Obfuscation Scanner (`string_entropy.py`)
- Analyzes extracted literal strings.
- Calculates Shannon Entropy to identify highly obfuscated, packed, or encrypted payloads.
- Uses regex to detect Base64 and Hex blob indicators.

### c) Certificate Scanner (`cert_scanner.py`)
- Integrates `androguard`'s certificate parsing to parse X.509 signatures within the APK's `META-INF/` folder.
- Extracts `SHA1`, `SHA256`, `MD5`, `Issuer`, `Subject`, and validates whether the certificate is self-signed (which triggers a high severity risk alert).

### d) Android Security Misconfiguration Audit (`manifest_check.py`)
- Explicitly flags critical Android manifest settings: `debuggable`, `allowBackup`, `usesCleartextTraffic`, `sharedUserId`, and exported components.
- Adds contextual severity mappings and remediation recommendations.

### e) Unified IOC Generation (`aggregator.py`)
- Aggregates Network (Domains, IPv4, URLs, Emails), Secrets, Hashes, and Certificates into a flat `ioc.json` and a user-downloadable `ioc.csv`.

## 3. Files Modified & Created
### Modified
- `backend/app/routes/static_analysis.py`: Enhanced pipeline orchestration and cleanup.
- `backend/app/static_analysis/code_analysis.py`: Added Apktool fallback and string extraction.
- `backend/app/static_analysis/manifest_check.py`: Added Security Misconfiguration auditing.
- `backend/app/static_analysis/aggregator.py`: Added IOC CSV generation and certificate/obfuscation risk scoring.
- `backend/app/routes/reporting.py`: Added IOC CSV and JSON endpoints.
- `backend/app/reporting/templates/report_template.html`: Designed visual elements for Misconfigurations, Certificates, Obfuscation, and IOCs.
- `frontend/src/api/client.js`: Wired up IOC endpoint URLs.
- `frontend/src/components/ReportViewer.jsx`: Added IOC download buttons.
- `frontend/src/components/ResultsPanel.jsx`: Rendered data visualizations for the new scanners.

### Created
- `backend/app/static_analysis/string_entropy.py`: Obfuscation detection.
- `backend/app/static_analysis/cert_scanner.py`: Certificate logic.

## 4. How to Run Locally

### Backend
To start the FastAPI engine and all analysis modules, open a terminal in the root directory:
```bash
cd backend
venv\Scripts\python.exe -m uvicorn backend.main:app --reload --port 8000
```
*Note: The backend must be run with the project root set as the PYTHONPATH to ensure `backend.x.y` imports resolve.*

### Frontend
To start the React frontend:
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:5173/` in your browser.

## 5. Known Limitations
- **WeasyPrint PDF Generation (Windows):** `WeasyPrint` heavily depends on GTK libraries which can be difficult to configure on Windows environments. The backend utilizes a `ReportLab` fallback if WeasyPrint fails. 
- **APKTool / Jadx execution speeds:** Large enterprise APKs (100MB+) may trigger the 120-second timeout during decompilation. Extending this timeout is trivial but slows down the synchronous pipeline. 
- **Dynamic Analysis:** Currently left untouched. This milestone focused strictly on 100% completion of the Static Analysis pipeline.
