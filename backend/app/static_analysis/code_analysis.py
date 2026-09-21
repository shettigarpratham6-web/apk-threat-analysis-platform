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
    
    if not os.path.exists(jadx_path):
        logger.error(f"Jadx not found at {jadx_path}")
        results["error"] = "Jadx executable not found."
        return results

    temp_dir = os.path.join(tempfile.gettempdir(), f"decompiled_{uuid.uuid4().hex}")
    extracted_strings = set()
    file_ext = ".java"
    
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
            
            # Run Apktool fallback
            cmd = [apktool_path, "d", "-s", "-f", "-o", temp_dir, apk_path]
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
                        
                    for line in lines:
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
                except Exception as e:
                    logger.warning(f"Failed to read {filepath}: {e}")
                    
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
