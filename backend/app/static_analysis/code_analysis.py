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
    "Runtime.exec": "Medium",
    "ProcessBuilder": "Medium",
    "DexClassLoader": "High",
    "PathClassLoader": "High",
    "WebView.loadUrl": "Low",
    "addJavascriptInterface": "High",
    "Cipher.getInstance": "Low",
    "SSLContext": "Low",
    "TrustManager": "Medium",
    "getSystemService(ACCESSIBILITY_SERVICE)": "High",
    "DevicePolicyManager": "High",
    "android.hardware.camera2": "Medium",
    "LocationManager": "Medium",
    "SmsManager": "High",
    "ClipboardManager": "Low",
    "NotificationListenerService": "High"
}

MALWARE_INDICATORS = {
    "java.lang.reflect": {"severity": "High", "reason": "Reflection can be used to hide malicious behavior."},
    "System.loadLibrary": {"severity": "High", "reason": "Native library loading detected."},
    "Base64.decode": {"severity": "Medium", "reason": "Base64 decoding often used for obfuscation."},
    "^": {"severity": "Low", "reason": "XOR operation detected (possible obfuscation).", "heuristic": True},
    "/system/bin/sh": {"severity": "Critical", "reason": "Shell command execution."},
    "/system/app/Superuser.apk": {"severity": "High", "reason": "Root detection check."},
    "qemu": {"severity": "Medium", "reason": "Emulator detection check."}
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
        # Try JADX first
        try:
            cmd = [jadx_path, "-d", temp_dir, "--no-res", "--no-imports", apk_path]
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
                                    
                        # Suspicious APIs
                        for api, severity in SUSPICIOUS_APIS.items():
                            if api in line_stripped:
                                results["suspicious_apis"].append({
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "snippet": line_stripped[:100],
                                    "severity": severity,
                                    "api": api
                                })
                                # Capture surrounding context for CodeBERT
                                ctx_start = max(0, idx - 4)
                                ctx_end = min(len(lines), idx + 8)
                                ctx_code = "".join(lines[ctx_start:ctx_end])

                                # LLM de-obfuscation: call for High-severity APIs that contain
                                # known obfuscation/exfiltration signals
                                llm_explanation = None
                                if (
                                    severity == "High"
                                    and _LLM_CODE_AVAILABLE
                                    and analyze_suspicious_code is not None
                                    and any(kw in ctx_code for kw in _LLM_TRIGGER_KEYWORDS)
                                ):
                                    try:
                                        llm_explanation = analyze_suspicious_code(ctx_code)
                                    except Exception as _llm_err:
                                        logger.warning(f"LLM code analysis skipped for {api}: {_llm_err}")

                                codebert_candidates.append({
                                    "code": ctx_code,
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "line_number": idx + 1,
                                    "api": api,
                                    "llm_explanation": llm_explanation,
                                })
                                
                        # Malware Indicators
                        for ind, meta in MALWARE_INDICATORS.items():
                            if meta.get("heuristic") and ind not in line_stripped:
                                continue
                            if ind in line_stripped and not meta.get("heuristic"):
                                results["malware_indicators"].append({
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "snippet": line_stripped[:100],
                                    "severity": meta["severity"],
                                    "why_flagged": meta["reason"]
                                })
                                ctx_start = max(0, idx - 4)
                                ctx_end = min(len(lines), idx + 8)
                                ctx_code = "".join(lines[ctx_start:ctx_end])

                                # LLM de-obfuscation: call for Critical/High malware indicators
                                # that carry recognised evasion or shell-execution signals
                                llm_explanation = None
                                if (
                                    meta["severity"] in ("Critical", "High")
                                    and _LLM_CODE_AVAILABLE
                                    and analyze_suspicious_code is not None
                                    and any(kw in ctx_code for kw in _LLM_TRIGGER_KEYWORDS)
                                ):
                                    try:
                                        llm_explanation = analyze_suspicious_code(ctx_code)
                                    except Exception as _llm_err:
                                        logger.warning(f"LLM code analysis skipped for indicator '{ind}': {_llm_err}")

                                codebert_candidates.append({
                                    "code": ctx_code,
                                    "class_name": class_name,
                                    "file_path": rel_path,
                                    "line_number": idx + 1,
                                    "why_flagged": meta["reason"],
                                    "llm_explanation": llm_explanation,
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

        # Run CodeBERT Semantic Similarity Analysis
        try:
            from backend.app.static_analysis.codebert_analyzer import get_codebert_analyzer
            cb_analyzer = get_codebert_analyzer()
            results["codebert_similarity"] = cb_analyzer.analyze_snippets_batch(codebert_candidates)
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
