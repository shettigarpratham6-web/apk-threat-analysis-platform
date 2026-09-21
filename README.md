# APK Threat Analysis Platform with C2 Detection

A comprehensive, automated platform for analyzing Android APKs through multi-stage static decompilation, dynamic sandboxing, Command and Control (C2) server detection, threat correlation, and forensic reporting.

---

## 📌 Overview

The **APK Threat Analysis Platform** provides cybersecurity analysts, threat researchers, and incident responders with an end-to-end framework to inspect Android applications (`.apk` files) for malicious behaviors, hidden C2 infrastructure, privacy violations, and suspicious API invocations.

The platform combines **static manifest & bytecode analysis**, **dynamic sandbox execution** (via Android Emulator, Frida instrumentation, and mitmproxy network interception), **C2 beacon detection**, **threat intelligence correlation** (VirusTotal & AbuseIPDB), and **interactive forensic visualization** via a React web UI and FastAPI REST service.

---

## ✨ Key Features

### 🔍 1. Static Analysis Engine
- **Manifest Auditing**: Extracts requested permissions, intent filters, exported components, services, and receivers.
- **Bytecode & Decompilation**: Scans DEX files for sensitive API calls (SMS interception, accessibility abuse, reflection, dynamic code loading).
- **YARA Signature Matching**: Matches custom YARA rules against unpacked APK assets and DEX files to identify known malware families.
- **Embedded Asset Extraction**: Extracts embedded URLs, hardcoded IP addresses, crypto wallets, and encrypted payloads.

### 🧪 2. Dynamic Sandbox & Network Interception
- **Emulator Execution**: Runs APKs in an isolated Android Virtual Device (AVD) environment.
- **Frida Dynamic Instrumentation**: Hooks runtime APIs to trace cryptographic operations, file access, SMS sending, and root detection bypasses.
- **Network Traffic Capture**: Intercepts HTTP/HTTPS/TCP traffic using `mitmproxy` with SSL unpinning scripts to inspect request headers, payloads, and TLS certificates.

### 📡 3. Command & Control (C2) Detection
- **Traffic Pattern Analysis**: Identifies beaconing behavior, domain generation algorithms (DGA), unusual TLS JA3/JA3S fingerprints, and raw IP communication.
- **Threat Intelligence Correlation**: Queries AbuseIPDB and VirusTotal APIs to score destination IPs, domains, and file hashes.

### 📊 4. Correlation Engine & Risk Scoring
- Correlates static permissions and code patterns with dynamic runtime behavior.
- Computes unified risk scores and threat levels (Critical, High, Medium, Low, Clean).
- Generates structured JSON and PDF forensic reports for incident response teams.

### 🖥️ 5. Web Dashboard & REST API
- **React Frontend**: Drag-and-drop APK upload, real-time analysis progress tracker, threat metrics dashboard, and interactive report viewer.
- **FastAPI Service**: Asynchronous execution pipeline, OpenAPI/Swagger documentation, and modular REST endpoints.

---

## 📁 Project Architecture & Structure

```
apk-threat-analysis-platform/
├── backend/                  # FastAPI service & analysis pipeline
│   ├── api/                  # REST API routes and endpoints
│   ├── core/                 # Core threat engine
│   │   ├── preprocessor/     # APK unzipping & DEX extraction
│   │   ├── static_analysis/  # Manifest parsing, YARA, bytecode scanner
│   │   ├── dynamic_analysis/ # Frida instrumentation & emulator controller
│   │   ├── c2_detection/     # C2 beaconing & network correlation
│   │   ├── correlation/      # Unified threat scoring engine
│   │   └── pipeline.py       # Main orchestration pipeline
│   ├── database/             # Report persistence and metadata store
│   ├── report/               # Forensic report generators (JSON / HTML)
│   ├── tasks/                # Asynchronous queue tasks
│   ├── utils/                # Helper utilities and external API clients
│   ├── config.py             # Global backend configuration
│   ├── main.py               # FastAPI entry point
│   └── requirements.txt      # Python dependencies
├── frontend/                 # React web application
│   ├── public/               # Static web assets
│   ├── src/                  # React components, pages, services
│   └── package.json          # Node dependencies & Vite scripts
├── sandbox/                  # Dynamic analysis environment
│   ├── emulator_config/      # AVD setup scripts & Android image profiles
│   ├── frida_scripts/        # Hooking scripts for SSL unpinning & API tracing
│   └── mitm_config/          # Proxy configuration & certificate injection
├── yara_rules/               # Malware detection rules (.yar files)
├── datasets/                 # Test APK samples (malware & benign)
├── docker/                   # Docker build definitions
│   ├── Dockerfile.backend    # Backend container definition
│   ├── Dockerfile.frontend   # Frontend container definition
│   └── docker-compose.yml    # Multi-container orchestrator
├── docs/                     # Documentation & API specs
├── tests/                    # Unit and integration tests
├── .env.example              # Environment variables template
├── .gitignore                # Git exclusion file
└── README.md                 # Project documentation
```

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend** | Python 3.11+, FastAPI, Uvicorn, Pydantic, YARA-Python, Python-Multipart |
| **Frontend** | React 18, Vite, Axios, Modern CSS |
| **Sandbox Environment** | Android Emulator (AVD), Frida, mitmproxy, ADB |
| **Threat Intelligence** | VirusTotal API, AbuseIPDB API |
| **Containerization** | Docker, Docker Compose |

---

## 🚀 Quick Start & Installation

### Prerequisites
- **Python** `^3.11`
- **Node.js** `^18.0` & **npm**
- **Docker** & **Docker Compose** *(optional, for containerized run)*
- **Android SDK & ADB** *(optional, required for local dynamic sandbox execution)*

---

### 🔧 1. Environment Setup

Copy `.env.example` to create your local `.env` configuration file:

```bash
cp .env.example .env
```

Edit `.env` to supply external threat intelligence credentials:

```env
# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Backend Security
API_KEY=your_optional_secret_api_key
```

---

### 💻 2. Running Locally (Development Mode)

#### A. Backend Setup
1. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Launch the FastAPI server:
   ```bash
   uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```
   - API Documentation (Swagger UI): `http://localhost:8000/docs`
   - Health Check: `http://localhost:8000/health`

#### B. Frontend Setup
1. Open a new terminal and navigate to the `frontend/` folder:
   ```bash
   cd frontend
   ```

2. Install Node packages:
   ```bash
   npm install
   ```

3. Start the Vite dev server:
   ```bash
   npm run dev
   ```
   - Access Web UI at: `http://localhost:5173`

---

### 🐳 3. Running via Docker Compose

To spin up the entire application stack (Backend & Frontend) using Docker:

```bash
docker-compose -f docker/docker-compose.yml up --build
```

- **Frontend UI**: `http://localhost:5173`
- **Backend API**: `http://localhost:8000`
- **API Interactive Docs**: `http://localhost:8000/docs`

---

## 🧪 Testing & Verification

Run automated backend tests using `pytest`:

```bash
pytest tests/
```

---

## 🛡️ Security & Ethical Disclaimer

> [!WARNING]
> This platform is designed **strictly for authorized cybersecurity research, malware analysis, educational, and defense purposes**. 
> Always execute potential malware samples inside isolated sandbox virtual machines. Do not connect untrusted devices or live production networks to malware testing environments.

---

## 📜 License

Distributed under the [MIT License](LICENSE).

