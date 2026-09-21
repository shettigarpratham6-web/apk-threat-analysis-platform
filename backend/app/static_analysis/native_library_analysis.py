"""Phase 7: Native Library Analysis Engine"""
import os
import hashlib
from typing import Dict, Any, List
from loguru import logger

def analyze_native_libs(extracted_dir: str) -> Dict[str, Any]:
    """Scans the lib/ directory for native architectures and suspicious libraries."""
    results = {
        "architectures": set(),
        "libraries": [],
        "suspicious_libraries": []
    }
    
    lib_dir = os.path.join(extracted_dir, "lib")
    if not os.path.exists(lib_dir):
        return {"architectures": [], "libraries": [], "suspicious_libraries": [], "message": "No native libraries found."}
        
    for root, _, files in os.walk(lib_dir):
        for file in files:
            if not file.endswith(".so"):
                continue
                
            filepath = os.path.join(root, file)
            abi = os.path.basename(root)
            results["architectures"].add(abi)
            
            size = os.path.getsize(filepath)
            sha256 = hashlib.sha256()
            
            with open(filepath, "rb") as f:
                content = f.read()
                sha256.update(content)
                
            is_suspicious = False
            reasons = []
            
            # Very basic heuristic for packed/suspicious
            if b"UPX!" in content:
                is_suspicious = True
                reasons.append("UPX Packed Library")
                
            if size < 5000:
                is_suspicious = True
                reasons.append("Unusually small library size (Possible shellcode loader)")
                
            lib_meta = {
                "name": file,
                "abi": abi,
                "size": size,
                "sha256": sha256.hexdigest(),
                "jni_usage": b"JNI_OnLoad" in content
            }
            results["libraries"].append(lib_meta)
            
            if is_suspicious:
                lib_meta["reasons"] = reasons
                results["suspicious_libraries"].append(lib_meta)
                
    results["architectures"] = list(results["architectures"])
    return results
