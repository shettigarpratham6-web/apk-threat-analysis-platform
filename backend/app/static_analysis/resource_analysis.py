"""Phase 6: Resource Analysis Engine"""
import os
import re
from typing import Dict, Any, List
from loguru import logger

# Secret Regex Patterns
SECRET_PATTERNS = {
    "Google API Key": r'AIza[0-9A-Za-z-_]{35}',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "AWS Access Key ID": r'AKIA[0-9A-Z]{16}',
    "JWT Token": r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Stripe Key": r'sk_live_[0-9a-zA-Z]{24}',
    "GitHub Token": r'ghp_[0-9a-zA-Z]{36}',
    "Generic Secret": r'(?i)(?:password|secret|token|api_key|apikey)["\s:=]+([^\s"<>]+)'
}

def scan_file_for_secrets(filepath: str) -> List[Dict[str, str]]:
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in set(matches):
                    # For generic secrets, we captured a group
                    val = match if isinstance(match, str) else str(match)
                    if len(val) > 4:  # Basic filter to avoid noise
                        findings.append({
                            "type": secret_type,
                            "value": val[:50] + "..." if len(val) > 50 else val
                        })
    except Exception:
        pass
    return findings

def analyze_resources(extracted_dir: str) -> Dict[str, Any]:
    """Scans extracted APK resources for secrets and configs."""
    results = {
        "secrets": [],
        "configurations": [],
        "certificates": []
    }
    
    target_dirs = ["assets", "res", "META-INF"]
    
    for target in target_dirs:
        target_path = os.path.join(extracted_dir, target)
        if not os.path.exists(target_path):
            continue
            
        for root, _, files in os.walk(target_path):
            for file in files:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, extracted_dir)
                
                # Secret scanning (all files in assets/res)
                if target in ["assets", "res"]:
                    file_secrets = scan_file_for_secrets(filepath)
                    for s in file_secrets:
                        results["secrets"].append({
                            "file": rel_path,
                            "type": s["type"],
                            "value": s["value"]
                        })
                
                # Config scanning
                if target in ["assets", "res"] and file.endswith((".json", ".xml", ".yaml", ".properties", ".env")):
                    results["configurations"].append({
                        "file": rel_path,
                        "type": os.path.splitext(file)[1][1:].upper()
                    })
                
                # Certificate scanning in META-INF
                if target == "META-INF" and file.endswith((".RSA", ".DSA", ".EC")):
                    results["certificates"].append({
                        "file": rel_path,
                        "status": "Present (Parsing requires pyOpenSSL implementation)"
                    })
                    
    return results
