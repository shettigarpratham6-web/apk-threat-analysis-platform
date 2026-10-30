"""Phase 1: String Entropy and Obfuscation Detection"""
import math
import re
from typing import Dict, Any, List

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def detect_obfuscation(strings_set: set) -> List[Dict[str, Any]]:
    findings = []
    
    # Simple regex for Base64 and Hex
    base64_pattern = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
    hex_pattern = re.compile(r'^[a-fA-F0-9]{32,}$')
    
    for s in strings_set:
        if len(s) < 20:
            continue
            
        entropy = calculate_shannon_entropy(s)
        
        # High entropy typically indicates packed or encrypted data
        if entropy > 5.5:
            reason = "High Shannon Entropy"
            if base64_pattern.match(s):
                reason = "Base64 Encoded & High Entropy"
            elif hex_pattern.match(s):
                reason = "Hex Blob"
                
            findings.append({
                "value": s[:50] + "..." if len(s) > 50 else s,
                "entropy": round(entropy, 2),
                "reason": reason
            })
            
    # Sort by entropy descending
    findings.sort(key=lambda x: x["entropy"], reverse=True)
    return findings[:50]  # Return top 50 most obfuscated strings to avoid huge JSONs
