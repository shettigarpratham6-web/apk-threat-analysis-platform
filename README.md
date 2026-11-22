# APK Threat Analysis Platform with C2 Detection

A comprehensive, automated platform for in-depth Android malware inspection, combining multi-stage static decompilation, Random Forest machine learning threat classification, AI-driven de-obfuscation and executive narratives, dynamic emulator sandboxing with live interactive device streaming, real-time Command and Control (C2) beaconing and DGA detection, multi-vector threat correlation, and multi-format forensic reporting.

---

## 📌 Overview

The **APK Threat Analysis Platform** provides cybersecurity analysts, incident response teams, and mobile reverse engineers with an end-to-end framework to dissect Android applications (`.apk` files) for malicious payloads, stealthy C2 backdoors, data exfiltration, privacy violations, and evasive behaviors.

The platform integrates:
- **10-Phase Static Analysis Pipeline**: AndroidManifest parsing, DEX bytecode decompilation via JADX, sensitive API auditing, certificate validation, and asset extraction.
- **Drebin-Trained Random Forest Threat Classifier**: 215-feature binary static vector evaluation producing calibrated malware probability scores.
- **AI-Powered Reasoning Layer**: OpenRouter integration leveraging Meta Llama 3.3 70B for executive threat narratives and Qwen 2.5 Coder 32B for reverse-engineering obfuscated code.
- **Dynamic Sandbox & Interactive Phone HUD**: Android Emulator (AVD) management with low-latency ADB screen streaming, interactive touch/tap dispatch, and responsive SVG canvas fallback.
- **Analyst Authentication & Route Protection**: Session management backed by signed HS256 JWT in `httpOnly` cookies (`apk_session`), bcrypt password hashing (cost 12), in-memory brute-force protection (5 failures / 15 min), and route authorization on all static, dynamic, correlation, and reporting endpoints.
- **C2 Detection & Behavioral Engine**: Mathematical beaconing interval jitter analysis, Shannon entropy Domain Generation Algorithm (DGA) detection, non-standard port auditing, and static-to-dynamic indicator cross-referencing.
- **Threat Intelligence & Server Reputation**: VirusTotal and AbuseIPDB querying with aggressive in-memory caching.
- **Unified Risk Correlation & Forensic Reporting**: Transparent scoring (0–100), MITRE ATT&CK mapping, and automated export to ReportLab PDF, interactive HTML, structured JSON, and IOC CSV.

---

## ✨ Key Features

### 🔍 1. Static Analysis Engine
- **Manifest Auditing**: Extracts requested permissions, dangerous permissions, exported components, intent filters, services, and broadcast receivers using Androguard.
- **DEX Decompilation**: Multi-threaded decompilation (JADX v1.4.7 with 4 worker threads, fallback to Apktool) extracting Java source and Smali bytecode.
- **Suspicious API & Method Detection**: Scans for reflection (`java.lang.reflect`), native code loading (`System.loadLibrary`), command execution (`Runtime.exec`, `ProcessBuilder`), dynamic code loading (`DexClassLoader`), SMS interception (`SmsManager`), accessibility abuse, and root detection (`/system/bin/su`, `Superuser.apk`).
- **Signature Engine (YARA + Pure-Python Fallback)**: Compiles native YARA rules when available, with an integrated pure-Python `plyara` regex/pattern fallback for seamless execution on modern environments (such as Python 3.14 on Windows).
- **Embedded Network Indicators**: Regex-based extraction of URLs, IPv4/IPv6 addresses, domain names, and developer emails.

### 🤖 2. Machine Learning & Semantic Code Intelligence
- **Drebin Random Forest Classifier**: Evaluates an exact 215-feature static feature vector (`static_feature_names.json`) against a pre-trained scikit-learn model (`static_malware_random_forest.pkl`), outputting calibrated malware vs. benign confidence probabilities.
- **CodeBERT Semantic Similarity**: Evaluates semantic similarity between extracted decompiled snippets and known malicious patterns (with a lightweight heuristic fallback engine when PyTorch is not loaded).
- **OpenRouter AI Reasoning**:
  - *Threat Narrative Synthesis*: Generates a 3-paragraph executive summary using `meta-llama/llama-3.3-70b-instruct`.
  - *Code De-obfuscation*: Analyzes obfuscated classes and cryptographic routines using `qwen/qwen-2.5-coder-32b-instruct`.

### 🧪 3. Dynamic Sandbox & Live Virtual Device
- **Automated Lifecycle Management**: Starts, boots, and polls Android Virtual Devices (AVD `malware_sandbox`), clears stale lock files, restores snapshots, and manages proxy routing.
- **Live Device Screen Streaming**: Asynchronous frame streaming with 350ms caching and an adaptive chained-polling architecture.
- **Interactive Phone HUD**: Allows direct mouse clicking and touch interaction on the web interface, dispatching taps to the emulator via ADB with optimistic ripple feedback.
- **Offline HUD Fallback**: Displays an interactive Cyber Sandbox SVG HUD phone canvas when the emulator is offline or booting, preventing 503 errors and broken image icons.
- **Frida & mitmproxy Ready**: Supports runtime method hooking, SSL unpinning, and HTTP/HTTPS network interception.

### 📡 4. Command & Control (C2) Detection Engine
- **Beaconing Pattern Analysis**: Groups network requests by destination host and calculates interval mean ($\mu$), variance ($\sigma^2$), and standard deviation/jitter ($\sigma$). Contacts $\ge 3$ times with low jitter ($\sigma \le 2.5\text{s}$ or $\sigma/\mu < 0.25$) are flagged with High confidence.
- **DGA Domain Detection**: Computes Shannon entropy ($H \ge 3.45\text{ bits/symbol}$), vowel-to-consonant ratios ($< 0.15$), and digit density to identify algorithmically generated domains.
- **Suspicious Port Auditing**: Monitors non-standard and backdoor egress ports (e.g., `1337`, `4444`, `5555`, `6667`, `8080`, `8888`, `9001`, `31337`).
- **Static-to-Dynamic Cross-Correlation**: Automatically matches runtime traffic destinations against hardcoded URLs and IPs discovered during DEX static decompilation.

### 📊 5. Risk Scoring & Forensic Reporting
- **Transparent Risk Scoring**: Normalized 0–100 composite score combining dangerous permissions, YARA matches, suspicious APIs, C2 hosts, server reputation, ML predictions, and confirmed multi-vector threats.
  - **0–25**: Low Risk | **26–50**: Medium Risk | **51–75**: High Risk | **76–100**: Critical Risk
- **Multi-Vector Threat Confirmation**: Correlates static declarations with runtime evidence (e.g., SMS trojan, Dropper, Active C2, Shell execution).
- **Multi-Format Export**: Generates professional ReportLab PDF reports, interactive browser-rendered HTML reports, full JSON forensic dumps (`_report.json`), and IOC exports (CSV & JSON).

### 🔐 6. Analyst Authentication & Session Security
- **Cookie Session Architecture**: Signed HS256 JWT stored in an `httpOnly`, `SameSite=Lax` cookie (`apk_session`), with optional `COOKIE_SECURE=true`. Enables seamless authorization for `<iframe>` report viewers and `<img>` device screen streams without requiring Bearer token headers.
- **Password Security**: Passwords hashed using `bcrypt` (12 rounds) with length (8–72 bytes) and complexity validation (letters + numbers).
- **Anti-Brute Force & Enumeration**: In-memory rate limiting allows maximum 5 failed attempts within a 15-minute rolling window per client IP and email. Constant-time dummy hash verification prevents timing-based user enumeration.
- **Route Authorization**: All static analysis, dynamic sandbox, correlation, and reporting endpoints are gated behind the `get_current_user` FastAPI dependency when `AUTH_PROTECT_API=true`.
- **Frontend Route Protection**: Hand-rolled React route guards bounce unauthenticated requests on `/test`, `/analysis`, and `/dashboard` to `/login?next=...`, with strict same-origin validation (`getSafeNext`) blocking open-redirect exploits.
- **Analyst Registration**: Built-in test account (`live_analyst@example.com` / `ValidPassword123`) or registration via the `/signup` screen with an authorized-use acknowledgment terms checkbox.

---

## 📁 Project Architecture & Structure

```
apk-threat-analysis-platform/
├── backend/                              # FastAPI service & backend pipeline
│   ├── app/                              # Production application modules
│   │   ├── correlation/                  # Evidence aggregator & risk scoring formula
│   │   │   ├── aggregator.py             # Multi-stage correlation & threat narrative
│   │   │   └── risk_scoring.py           # Weighted 0-100 risk scoring algorithm
│   │   ├── dynamic_analysis/             # Sandbox, network, and C2 modules
│   │   │   ├── apk_runner.py             # APK installation & execution helper
│   │   │   ├── c2_detection.py           # Mathematical beaconing & DGA detection
│   │   │   ├── frida_monitor.py          # Frida instrumentation & hook manager
│   │   │   ├── network_monitor.py        # mitmproxy trace processor
│   │   │   ├── sandbox_manager.py        # AVD lifecycle & ADB command manager
│   │   │   └── server_reputation.py      # VirusTotal & AbuseIPDB cached client
│   │   ├── reporting/                    # Forensic reporting engine
│   │   │   ├── report_generator.py       # ReportLab PDF & HTML compilation
│   │   │   └── templates/                # Jinja2 HTML report templates
│   │   ├── routes/                       # FastAPI REST API endpoints
│   │   │   ├── auth.py                   # /api/auth login, signup, logout, and me routes
│   │   │   ├── correlation.py            # /api/correlation routes
│   │   │   ├── dynamic_analysis.py       # /api/dynamic-analysis routes & phone HUD
│   │   │   ├── reporting.py              # /api/report download & view routes
│   │   │   └── static_analysis.py        # /api/static-analysis upload & analyze
│   │   └── static_analysis/              # Static inspection engines
│   │       ├── aggregator.py             # Phase 10 risk & IOC aggregation
│   │       ├── apk_extractor.py          # Zip-slip protected APK unpacking & hashing
│   │       ├── cert_scanner.py           # X.509 certificate & signature auditing
│   │       ├── codebert_analyzer.py      # Pretrained CodeBERT / heuristic similarity
│   │       ├── code_analysis.py          # JADX/Apktool decompilation & regex scanner
│   │       ├── llm_analyzer.py           # OpenRouter AI integration (Llama 3.3 / Qwen)
│   │       ├── manifest_check.py         # Androguard AndroidManifest parser
│   │       ├── native_library_analysis.py# ELF .so shared object scanner
│   │       ├── resource_analysis.py      # XML layout and asset scanner
│   │       ├── signature_check.py        # YARA engine with pure-Python plyara fallback
│   │       └── string_entropy.py         # Shannon entropy obfuscation detector
│   ├── core/                             # Core pipeline & ML classifier
│   │   └── static_analysis/
│   │       └── ml_classifier.py          # Random Forest 215-feature Drebin classifier
│   ├── database/                         # Database and ORM layer
│   │   ├── crud.py                       # User database queries and updates
│   │   ├── database.py                   # SQLAlchemy engine, sessionmaker, and get_db dependency
│   │   └── models.py                     # SQLAlchemy User model
│   ├── data/                             # SQLite persistent database storage (app.db)
│   ├── results/                          # Generated JSON, HTML, PDF & IOC reports
│   ├── uploads/                          # Temporary uploaded APK storage
│   ├── main.py                           # FastAPI application entry point, CORS & auth router
│   └── requirements.txt                  # Python package dependencies
├── frontend/                             # React + Vite web application
│   ├── public/                           # Static assets and icons
│   ├── src/
│   │   ├── api/                          # REST client & fetch helpers
│   │   │   ├── auth.js                   # Authentication API endpoints (login, signup, logout, me)
│   │   │   └── client.js                 # Unified API client with credentials inclusion
│   │   ├── auth/                         # Session context & route guards
│   │   │   └── AuthContext.jsx           # AuthProvider & getSafeNext open-redirect protection
│   │   ├── components/                   # React UI components
│   │   │   ├── LiveVirtualDevice.jsx     # Live Android phone HUD & touch controller
│   │   │   ├── PipelineStepper.jsx       # Multi-stage analysis step indicator
│   │   │   ├── ResultsPanel.jsx          # Tabbed inspection view
│   │   │   ├── RiskBanner.jsx            # Threat badge & score display
│   │   │   ├── ThreatDashboard.jsx       # Threat metrics & C2 indicators
│   │   │   ├── UploadAPK.jsx             # Drag-and-drop file upload zone
│   │   │   └── IOCTable.jsx              # Extracted Indicators of Compromise table
│   │   ├── hooks/                        # Shared custom hooks
│   │   │   └── useVantaGlobe.js          # Shared Vanta 3D globe background hook
│   │   ├── pages/                        # Application pages
│   │   │   ├── AuthPage.jsx              # Cyberpunk Login & Signup interface
│   │   │   ├── AuthPage.css              # Glass card styling & password strength meter
│   │   │   ├── LandingPage.jsx           # Cyber landing page with auth-aware navigation
│   │   │   ├── LandingPage.css           # Full-page cybersecurity animated styling
│   │   │   ├── Analysis.jsx              # Real-time static & dynamic workflow page
│   │   │   ├── Report.jsx                # Forensic report view & download page
│   │   │   └── TestingDashboard.jsx      # Testing dashboard with LOGOUT action
│   │   ├── App.jsx                       # Hand-rolled routing & route guards
│   │   └── main.jsx                      # React DOM mount point with AuthProvider
│   └── package.json                      # Frontend dependencies & Vite scripts
├── ml/                                   # Machine Learning artifacts
│   └── models/
│       ├── static_malware_random_forest.pkl # Serialized Random Forest model (scikit-learn 1.9.1)
│       └── static_feature_names.json     # List of 215 Drebin benchmark feature keys
├── sandbox/                              # Sandbox configuration & CLI tools
│   ├── adb_helper.py                     # Low-level ADB wrappers
│   ├── apk_analyzer.py                   # Standalone CLI APK analyzer
│   ├── c2_detector.py                    # Standalone C2 detector class
│   ├── cert_installer.py                 # mitmproxy CA certificate installer
│   ├── emulator_config.py                # Sandbox configuration constants
│   ├── frida_helper.py                   # Frida script deployment helper
│   ├── network_analyzer.py               # PCAP and flow analyzer
│   └── mitm_config/                      # mitmproxy addon scripts
├── tools/                                # External binary tooling
│   └── jadx/                             # JADX DEX decompiler v1.4.7
│       └── bin/jadx.bat                  # JADX Windows executable
├── yara_rules/                           # Malware signature detection rules
│   ├── c2_beaconing.yar                  # C2 domain and URI pattern rules
│   ├── generic_android_malware.yar       # Su binary, root check, dropper rules
│   └── suspicious_permissions.yar        # Combined SMS and boot action rules
├── datasets/                             # Test APK samples
│   ├── benign/                           # Benign test APKs (e.g. BenignDemo.apk)
│   └── malicious/                        # Malicious test APKs (e.g. C2Simulator.apk)
├── tests/                                # Automated test suite (64 tests)
│   ├── conftest.py                       # Test bootstrap & environment configuration
│   ├── test_auth.py                      # Authentication, lockout & session test suite
│   ├── test_static_analysis.py           # Static pipeline & manifest parsing tests
│   ├── test_dynamic_analysis.py          # Dynamic sandbox & screen tests
│   ├── test_c2_detector.py               # C2 beaconing & network tests
│   ├── test_ml_classifier.py             # Random Forest 215-feature tests
│   ├── test_correlation.py               # Risk correlation & threat scoring tests
│   ├── test_codebert_analyzer.py         # Semantic CodeBERT similarity tests
│   ├── test_reporting.py                 # PDF/HTML report generation tests
│   └── test_dashboard.py                 # Dashboard data aggregation tests
├── .env.example                          # Environment variables template
├── .gitignore                            # Git exclusion patterns
└── README.md                             # Project documentation
```

---

## 🛠️ Technology Stack

| Component | Technology | Version / Details |
| :--- | :--- | :--- |
| **Backend Framework** | FastAPI + Uvicorn | High-performance asynchronous REST service |
| **Python Runtime** | Python | 3.11 – 3.14+ (fully verified) |
| **APK Parsing** | Androguard | v4.x (Binary XML, resources, DEX classes) |
| **Decompilation** | JADX | v1.4.7 (Multi-threaded Java bytecode decompilation) |
| **Machine Learning** | scikit-learn + Joblib | Random Forest model trained on 215 Drebin features |
| **Signature Engine** | YARA / Plyara | Native YARA with pure-Python Plyara rule fallback |
| **AI Reasoning** | OpenRouter API | Meta Llama 3.3 70B & Qwen 2.5 Coder 32B |
| **Forensic PDF** | ReportLab | Automated PDF generation with risk banners and tables |
| **Dynamic Sandbox** | Android SDK & ADB | AVD execution, screencap caching, touch dispatch |
| **Traffic Interception**| mitmproxy & Frida | SSL unpinning and live request stream capture |
| **Threat Intelligence**| VirusTotal & AbuseIPDB | In-memory cached IP and domain scoring |
| **Database & ORM** | SQLAlchemy 2 + SQLite | Declarative ORM, session management, and persistent user store |
| **Authentication & JWT**| PyJWT + bcrypt | HS256 signed httpOnly cookies, bcrypt hashing (cost 12) |
| **Frontend UI** | React 18 + Vite | Cyber glassmorphism HUD, interactive phone screen |

---

## 🚀 Installation & Local Setup

### Prerequisites
- **Python** `3.11+` (Python `3.14` supported)
- **Node.js** `18.0+` & **npm**
- **Android SDK & ADB** *(optional, required for local dynamic sandbox execution)*
  - Default ADB Path: `C:\Users\<user>\AppData\Local\Android\Sdk\platform-tools\adb.exe`
  - Default Emulator: `C:\Users\<user>\AppData\Local\Android\Sdk\emulator\emulator.exe`
- **Java JRE / JDK 11+** *(required for JADX decompilation)*

---

### 1. Environment Configuration

Copy `.env.example` to create your local `.env` configuration file:

```bash
# On Windows (PowerShell):
Copy-Item .env.example .env

# On Linux/macOS:
cp .env.example .env
```

Edit `.env` to configure your environment:

```env
# Threat Intelligence API Keys (Optional)
VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
ABUSEIPDB_API_KEY="your_abuseipdb_api_key_here"

# OpenRouter AI Key (Optional - enables AI threat narrative & code de-obfuscation)
OPENROUTER_API_KEY="your_openrouter_api_key_here"

# Android Emulator Sandbox Configuration
ANDROID_EMULATOR_PATH="C:\Users\<username>\AppData\Local\Android\Sdk\emulator\emulator.exe"
ADB_PATH="C:\Users\<username>\AppData\Local\Android\Sdk\platform-tools\adb.exe"
AVD_NAME="malware_sandbox"
SNAPSHOT_NAME="clean_state"
HEADLESS_MODE=true

# Service URLs
API_BASE_URL="http://localhost:8000"
VITE_API_BASE_URL="http://localhost:8000"

# Authentication & Session Configuration
# Generate a secret with: python -c "import secrets; print(secrets.token_urlsafe(48))"
JWT_SECRET="your_random_48_char_secret_here"
JWT_EXPIRE_MINUTES=480
COOKIE_SECURE=false
AUTH_PROTECT_API=true
DATABASE_URL=""
```

> **Default Pre-Configured Analyst Account:**  
> - **Email:** `live_analyst@example.com`  
> - **Password:** `ValidPassword123`  
> You can also register a new analyst account directly on the web application at [http://localhost:5173/signup](http://localhost:5173/signup).

---

### 2. Backend Setup & Startup

1. Create and activate a Python virtual environment:
   ```powershell
   # Windows (PowerShell):
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux/macOS:
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install backend dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Start the FastAPI backend server:
   ```powershell
   # Windows (PowerShell):
   $env:PYTHONPATH = "."
   .\venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

   # Linux/macOS:
   PYTHONPATH="." uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
   ```

- **API Root**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

### 3. Frontend Setup & Startup

1. Open a second terminal and navigate to `frontend/`:
   ```bash
   cd frontend
   ```

2. Install Node packages:
   ```bash
   npm install
   ```

3. Launch the Vite development server:
   ```bash
   npm run dev
   ```

- **Application Web UI**: [http://localhost:5173](http://localhost:5173)

---

## 🧪 Automated Testing & Verification

The repository contains 64 comprehensive unit and integration tests covering user authentication & brute-force protection, static parsing, JADX decompilation, the 215-feature Random Forest classifier, C2 beaconing algorithms, risk correlation formulas, ReportLab PDF compilation, and dynamic screen streaming.

Run the complete test suite:

```powershell
# Windows (PowerShell):
$env:PYTHONPATH = "."
.\venv\Scripts\pytest.exe -v

# Linux/macOS:
PYTHONPATH="." pytest -v
```

**Expected Result:**
```text
============================== 64 passed in ~43s ==============================
```

---

## 📡 REST API Reference

### Authentication & Session Management
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/signup` | Registers a new analyst account and sets the signed `apk_session` httpOnly cookie. |
| `POST` | `/api/auth/login` | Validates credentials (with rate-limiting) and sets the `apk_session` httpOnly cookie. |
| `POST` | `/api/auth/logout` | Clears the `apk_session` session cookie. |
| `GET`  | `/api/auth/me` | Returns current analyst user profile (`id`, `email`, `full_name`, `created_at`). |

> **Route Protection Note:** When `AUTH_PROTECT_API=true` (default), all analysis routes (`/api/static-analysis/*`, `/api/dynamic-analysis/*`, `/api/correlation/*`, and `/api/report/*`) require an active session cookie or Bearer token (unauthenticated requests return `401 Unauthorized`). The `/health` endpoint remains public.

### Static Analysis
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/static-analysis/analyze` | Executes the complete 10-phase static analysis pipeline (Manifest, DEX, YARA, ML, IOCs, Report). |
| `POST` | `/api/static-analysis/upload` | Validates, hashes (SHA-256/MD5), and unpacks an APK without running full analysis. |
| `POST` | `/api/static-analysis/codebert-similarity` | Evaluates semantic similarity of a code snippet against known malware patterns. |

### Dynamic Analysis & Live Sandbox
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/dynamic-analysis/sandbox/start` | Boots the Android emulator and verifies ADB connectivity. |
| `POST` | `/api/dynamic-analysis/sandbox/stop` | Terminates emulator processes and cleans up AVD lock files. |
| `POST` | `/api/dynamic-analysis/run` | Installs and launches the APK inside the active sandbox. |
| `POST` | `/api/dynamic-analysis/monitor` | Captures runtime API invocations, file operations, and network flows. |
| `POST` | `/api/dynamic-analysis/c2-detect` | Analyzes captured traffic for beaconing jitter, DGA entropy, and egress ports. |
| `POST` | `/api/dynamic-analysis/check-servers` | Queries VirusTotal and AbuseIPDB for reputation scores on observed IPs. |
| `GET`  | `/api/dynamic-analysis/screen/current` | Returns the current phone screen (cached ADB screenshot or responsive SVG HUD). |
| `POST` | `/api/dynamic-analysis/screen/touch` | Dispatches simulated tap/touch coordinates `(x, y)` to the emulator. |
| `GET`  | `/api/dynamic-analysis/screen/info` | Queries device window state, screen resolution, and current package. |

### Correlation & Reporting
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/correlation/correlate/{apk_id}` | Combines static + dynamic evidence, computes unified risk, and calls AI reasoning layer. |
| `POST` | `/api/report/generate/{apk_id}` | Compiles ReportLab PDF, HTML report, IOC JSON, and IOC CSV artifacts. |
| `GET`  | `/api/report/download/{apk_id}?format=pdf` | Downloads the forensic report in PDF, JSON, or CSV format. |
| `GET`  | `/api/report/view/{apk_id}` | Renders the HTML report directly in the browser. |
| `GET`  | `/health` | Health check endpoint returning `{"status": "ok"}`. |

---

## 📊 Threat Scoring & Risk Model

The platform uses a transparent, auditable formula bounded between `0` and `100`:

$$\text{Risk Score} = \min\left(100, \sum w_i \cdot \text{Score}_i\right)$$

| Contributing Factor | Weight / Formula | Cap |
| :--- | :--- | :--- |
| **Dangerous Permissions** | +10 per declared dangerous permission | +30 pts |
| **YARA Signature Matches** | +25 per matched malware rule | No cap |
| **VirusTotal Detections** | +30 if $\ge 1$ security vendors flag the APK hash | +30 pts |
| **Suspicious API Calls** | +5 per dangerous Dalvik API invocation in DEX code | +20 pts |
| **C2 Beaconing Hosts** | +10 (Low), +20 (Medium), +35 (High Confidence) | No cap |
| **Server Reputation** | +25 per malicious IP/domain, +10 per suspicious host | No cap |
| **Random Forest ML** | Up to +20 points proportional to model probability | +20 pts |
| **Confirmed Multi-Vector Threats** | +15 per verified static+dynamic alignment (e.g. SMS Trojan, Active C2) | +30 pts |

### Risk Classification Tiers
- 🟢 **0 – 25**: **Low Risk (Benign / Low Suspicion)**
- 🟡 **26 – 50**: **Medium Risk (Suspicious Capabilities)**
- 🟠 **51 – 75**: **High Risk (Probable Malware / Dangerous Permissions)**
- 🔴 **76 – 100**: **Critical Risk (Confirmed Malware / Active C2 Beaconing)**

---

## 🛡️ Security & Ethical Disclaimer

> [!WARNING]
> This platform is developed **strictly for authorized cybersecurity research, incident response, academic study, and defense purposes**.
> Always execute untrusted APK samples within an isolated virtual machine or dedicated sandbox environment. Never connect an analysis sandbox directly to corporate or production networks.

---

## 📜 License

Distributed under the [MIT License](LICENSE).
