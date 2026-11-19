"""Phase 5: DEX Code Analysis Engine (Hybrid Jadx/Apktool + Obfuscation)"""
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from typing import Dict, Any, List, Set
from loguru import logger

from backend.app.static_analysis.string_entropy import detect_obfuscation

try:
    from backend.app.static_analysis.llm_analyzer import analyze_suspicious_code
    _LLM_CODE_AVAILABLE = True
except Exception:
    _LLM_CODE_AVAILABLE = False
    analyze_suspicious_code = None  # type: ignore

# Obfuscation trigger keywords — snippets containing these strings qualify for LLM analysis
_LLM_TRIGGER_KEYWORDS = (
    "Base64", "base64", ".exec(", "loadLibrary", "DexClassLoader",
    "reflect", "/system/bin/sh", "su -c", "SmsManager", "sendTextMessage",
    "AccessibilityEvent", "ClipboardManager", "DevicePolicyManager",
)

# Indicators
NETWORK_PATTERNS = {
    "urls": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    "domains": r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',
    "ipv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "ipv6": r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b',
    "emails": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
}

SUSPICIOUS_APIS = {
    "Runtime.exec": {
        "severity": "Medium",
        "category": "Command Execution",
        "rationale": "Executes arbitrary native system commands or shell scripts, bypassing standard Android security sandboxing.",
    },
    "ProcessBuilder": {
        "severity": "Medium",
        "category": "Process Spawning",
        "rationale": "Spawns child processes to run low-level OS utilities or drop secondary binaries.",
    },
    "DexClassLoader": {
        "severity": "High",
        "category": "Dynamic Code Loading",
        "rationale": "Loads uncompiled classes and DEX payloads from storage or network dynamically at runtime, a hallmark of evasive malware.",
    },
    "PathClassLoader": {
        "severity": "High",
        "category": "Dynamic Code Loading",
        "rationale": "Loads external classes into memory, potentially executing untrusted third-party bytecode.",
    },
    "WebView.loadUrl": {
        "severity": "Low",
        "category": "Embedded Web View",
        "rationale": "Loads external URLs into in-app webviews; if unvalidated, can lead to cross-site scripting or remote code execution.",
    },
    "addJavascriptInterface": {
        "severity": "High",
        "category": "WebView Bridge",
        "rationale": "Exposes Java objects to untrusted JavaScript running inside WebView, potentially enabling full device takeover on older API levels.",
    },
    "Cipher.getInstance": {
        "severity": "Low",
        "category": "Cryptographic Operations",
        "rationale": "Initializes cryptographic cipher; commonly used for AES/DES encryption of exfiltrated data or command-and-control communications.",
    },
    "SSLContext": {
        "severity": "Low",
        "category": "Network Security",
        "rationale": "Manages TLS/SSL socket configuration; frequently manipulated to disable certificate pinning or bypass HTTPS verification.",
    },
    "TrustManager": {
        "severity": "Medium",
        "category": "Certificate Validation Bypass",
        "rationale": "Custom X509TrustManager implementations frequently accept all certificates, exposing network traffic to man-in-the-middle attacks.",
    },
    "getSystemService(ACCESSIBILITY_SERVICE)": {
        "severity": "High",
        "category": "Accessibility Hijacking",
        "rationale": "Requests accessibility manager to scrape screen content, log keystrokes, and automate user touches without authorization.",
    },
    "DevicePolicyManager": {
        "severity": "High",
        "category": "Device Administration Abuse",
        "rationale": "Acquires device admin privileges, commonly abused by ransomware to lock screens or prevent app uninstallation.",
    },
    "android.hardware.camera2": {
        "severity": "Medium",
        "category": "Surveillance / Spyware",
        "rationale": "Direct hardware camera access enabling covert background photo/video surveillance.",
    },
    "LocationManager": {
        "severity": "Medium",
        "category": "Geo-Tracking",
        "rationale": "Harvests precise latitude/longitude coordinates for unauthorized user location tracking.",
    },
    "SmsManager": {
        "severity": "High",
        "category": "SMS Toll Fraud / Exfiltration",
        "rationale": "Sends SMS messages without user interaction, frequently abused to send premium rate texts or steal 2FA codes.",
    },
    "ClipboardManager": {
        "severity": "Low",
        "category": "Clipboard Scraping",
        "rationale": "Reads copied text from clipboard buffer, risking exposure of passwords, crypto addresses, and tokens.",
    },
    "NotificationListenerService": {
        "severity": "High",
        "category": "Notification Interception",
        "rationale": "Intercepts incoming status bar notifications, allowing silent theft of OTPs and personal messaging alerts.",
    },
}

MALWARE_INDICATORS = {
    "java.lang.reflect": {
        "severity": "High",
        "category": "Dynamic Reflection",
        "reason": "Java Reflection allows hidden invocation of private or restricted Android APIs at runtime, evading static detection.",
    },
    "System.loadLibrary": {
        "severity": "High",
        "category": "Native Code Execution",
        "reason": "Loads shared native ELF libraries (.so) which can execute arbitrary C/C++ code outside the Dalvik/ART sandbox.",
    },
    "Base64.decode": {
        "severity": "Medium",
        "category": "Obfuscation / Decryption",
        "reason": "Decodes base64-encoded strings, commonly used to conceal malicious payload URLs, shellcode, and C2 server domains.",
    },
    "^": {
        "severity": "Low",
        "category": "XOR Encryption",
        "reason": "Bitwise XOR operation detected, frequently used as lightweight string encryption to obfuscate sensitive assets.",
        "heuristic": True,
    },
    "/system/bin/sh": {
        "severity": "Critical",
        "category": "Interactive Shell Access",
        "reason": "Invokes the Android Unix shell interpreter, enabling command execution with device-level privileges.",
    },
    "/system/app/Superuser.apk": {
        "severity": "High",
        "category": "Root Detection / Evasion",
        "reason": "Checks for Superuser/su binaries to verify root status and alter behavior in defensive or analytical sandboxes.",
    },
    "qemu": {
        "severity": "Medium",
        "category": "Emulator / Sandbox Evasion",
        "reason": "Inspects system properties for QEMU/Goldfish hypervisor artifacts to detect and evade virtual analysis sandboxes.",
    },
}

def analyze_code(apk_path: str) -> Dict[str, Any]:
    """Decompiles APK using Jadx (with Apktool fallback) and scans code for indicators."""
    results = {
        "network_indicators": {"urls": [], "domains": [], "ipv4": [], "ipv6": [], "emails": []},
        "suspicious_apis": [],
        "malware_indicators": [],
        "obfuscation_findings": [],
        "fallback_used": False
    }
    
    jadx_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "jadx", "bin", "jadx.bat" if os.name == "nt" else "jadx"))
    apktool_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "apktool", "apktool.bat" if os.name == "nt" else "apktool"))
    apktool_jar = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "apktool.jar"))
    
    if not os.path.exists(jadx_path):
        logger.error(f"Jadx not found at {jadx_path}")
        results["error"] = "Jadx executable not found."
        return results

    temp_dir = os.path.join(tempfile.gettempdir(), f"decompiled_{uuid.uuid4().hex}")
    extracted_strings = set()
    file_ext = ".java"
    
    results["codebert_similarity"] = {
        "status": "active",
        "matches": [],
        "suspicious_matches_found": 0,
        "max_confidence_score": 0.0,
    }
    codebert_candidates = []

    try:
        # Try JADX first (parallelized with 4 worker threads for fast de-compilation)
        try:
            cmd = [jadx_path, "-d", temp_dir, "--no-res", "--no-imports", "--threads-count", "4", apk_path]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=True)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            logger.warning(f"Jadx failed or timed out ({str(e)}). Falling back to Apktool.")
            results["fallback_used"] = True
            file_ext = ".smali"
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Run Apktool fallback (supports apktool binary or java -jar apktool.jar)
            if os.path.exists(apktool_path):
                cmd = [apktool_path, "d", "-s", "-f", "-o", temp_dir, apk_path]
            elif os.path.exists(apktool_jar):
                cmd = ["java", "-jar", apktool_jar, "d", "-s", "-f", "-o", temp_dir, apk_path]
            else:
                cmd = ["apktool", "d", "-s", "-f", "-o", temp_dir, apk_path]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            
        # Scan files (Java or Smali)
        for root_dir, dirs, files in os.walk(temp_dir):
            for file in files:
                if not file.endswith(file_ext):
                    continue
                    
                filepath = os.path.join(root_dir, file)
                rel_path = os.path.relpath(filepath, temp_dir)
                class_name = os.path.splitext(file)[0]
                
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        
                    for idx, line in enumerate(lines):
                        line_stripped = line.strip()
                        if not line_stripped or line_stripped.startswith(("#", "//", ".")):
                            continue
                            
                        # Extract strings for entropy analysis ("...")
                        str_matches = re.findall(r'"([^"]*)"', line_stripped)
                        for s in str_matches:
                            if len(s) >= 20:
                                extracted_strings.add(s)
                            
                        # Network Indicators
                        for key, pattern in NETWORK_PATTERNS.items():
                            matches = re.findall(pattern, line_stripped)
                            for match in matches:
                                if match not in results["network_indicators"][key]:
                                    results["network_indicators"][key].append(match)
                                    
                        # Suspicious APIs with detailed security evidence
                        for api, meta in SUSPICIOUS_APIS.items():
                            if api in line_stripped:
                                severity = meta["severity"] if isinstance(meta, dict) else meta
                                category = meta.get("category", "General") if isinstance(meta, dict) else "General"
                                rationale = meta.get("rationale", "") if isinstance(meta, dict) else ""

                                results["suspicious_apis"].append({
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "line_number": idx + 1,
                                    "snippet": line_stripped[:120],
                                    "severity": severity,
                                    "category": category,
                                    "rationale": rationale,
                                    "api": api,
                                })
                                # Capture surrounding context for CodeBERT and AI analysis
                                ctx_start = max(0, idx - 4)
                                ctx_end = min(len(lines), idx + 8)
                                ctx_code = "".join(lines[ctx_start:ctx_end])

                                codebert_candidates.append({
                                    "code": ctx_code,
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "line_number": idx + 1,
                                    "api": api,
                                    "severity": severity,
                                    "category": category,
                                    "has_trigger": any(kw in ctx_code for kw in _LLM_TRIGGER_KEYWORDS),
                                })
                                
                        # Malware Indicators with detailed rationales
                        for ind, meta in MALWARE_INDICATORS.items():
                            if meta.get("heuristic") and ind not in line_stripped:
                                continue
                            if ind in line_stripped and not meta.get("heuristic"):
                                results["malware_indicators"].append({
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "line_number": idx + 1,
                                    "snippet": line_stripped[:120],
                                    "severity": meta["severity"],
                                    "category": meta.get("category", "Malware Indicator"),
                                    "why_flagged": meta["reason"],
                                })
                                ctx_start = max(0, idx - 4)
                                ctx_end = min(len(lines), idx + 8)
                                ctx_code = "".join(lines[ctx_start:ctx_end])

                                codebert_candidates.append({
                                    "code": ctx_code,
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "line_number": idx + 1,
                                    "why_flagged": meta["reason"],
                                    "severity": meta["severity"],
                                    "category": meta.get("category", "Malware Indicator"),
                                    "has_trigger": any(kw in ctx_code for kw in _LLM_TRIGGER_KEYWORDS),
                                })

                    # If no suspicious API triggered, sample file if small
                    if len(codebert_candidates) < 5 and len(lines) > 5 and len(lines) < 80:
                        codebert_candidates.append({
                            "code": "".join(lines[:40]),
                            "class_name": class_name,
                            "file_path": rel_path,
                            "line_number": 1,
                        })

                except Exception as e:
                    logger.warning(f"Failed to read {filepath}: {e}")

        # Targeted, non-blocking LLM de-obfuscation: analyze AT MOST the top 1 highest-impact candidate
        results["ai_code_insight"] = None
        if _LLM_CODE_AVAILABLE and analyze_suspicious_code is not None and codebert_candidates:
            # Score candidates to pick the single most critical snippet
            def _candidate_score(cand):
                score = 0
                if cand.get("severity") == "Critical":
                    score += 15
                elif cand.get("severity") == "High":
                    score += 8
                if cand.get("has_trigger"):
                    score += 5
                return score

            best_candidate = max(codebert_candidates, key=_candidate_score, default=None)
            if best_candidate and _candidate_score(best_candidate) >= 8:
                try:
                    logger.info(f"Generating LLM de-obfuscation insight for top candidate in {best_candidate.get('class_name')}...")
                    explanation = analyze_suspicious_code(best_candidate["code"])
                    best_candidate["llm_explanation"] = explanation
                    results["ai_code_insight"] = {
                        "class_name": best_candidate.get("class_name"),
                        "file_path": best_candidate.get("file_path"),
                        "line_number": best_candidate.get("line_number"),
                        "api": best_candidate.get("api") or best_candidate.get("why_flagged"),
                        "explanation": explanation,
                    }
                except Exception as _llm_err:
                    logger.warning(f"Targeted LLM code analysis skipped: {_llm_err}")

        # Run CodeBERT Semantic Similarity Analysis
        try:
            from backend.app.static_analysis.codebert_analyzer import get_codebert_analyzer
            cb_analyzer = get_codebert_analyzer()
            # Pass only top candidate snippets (max 8) to keep similarity inference fast
            results["codebert_similarity"] = cb_analyzer.analyze_snippets_batch(codebert_candidates[:8])
        except Exception as cb_err:
            logger.warning(f"CodeBERT analysis failed: {cb_err}")
            results["codebert_similarity"] = {
                "status": "fallback",
                "fallback_reason": str(cb_err),
                "matches": [],
                "suspicious_matches_found": 0,
                "disclaimer": "Semantic similarity analysis fallback active.",
            }
                    
    except Exception as e:
        logger.error(f"Error in code analysis: {e}")
        results["error"] = str(e)
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    # Deduplicate network lists
    for k in results["network_indicators"]:
        results["network_indicators"][k] = list(set(results["network_indicators"][k]))
        
    # Run Obfuscation / Entropy Detection
    results["obfuscation_findings"] = detect_obfuscation(extracted_strings)
        
    return results
