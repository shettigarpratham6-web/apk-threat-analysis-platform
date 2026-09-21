"""Phase 9: Static Risk Correlation Engine"""
from typing import Dict, Any, List

def calculate_risk(manifest: Dict, code: Dict, resources: Dict, natives: Dict, yara: List, certs: List) -> Dict[str, Any]:
    """Calculates risk score 0-100 based on all static analysis findings."""
    score = 0
    factors = []
    recommendations = set()
    
    # 1. Manifest Analysis
    if manifest.get("permissions"):
        for perm in manifest["permissions"]:
            if perm.get("severity") == "Critical":
                score += 15
                factors.append(f"Critical permission: {perm['name']}")
                recommendations.add(f"Review necessity of {perm['name']}")
            elif perm.get("severity") == "High":
                score += 10
                factors.append(f"High risk permission: {perm['name']}")
                
    if manifest.get("security_flags", {}).get("debuggable") == True:
        score += 10
        factors.append("App is debuggable (android:debuggable=true)")
        recommendations.add("Set android:debuggable to false for release.")
        
    if manifest.get("security_flags", {}).get("allowBackup") == True:
        score += 5
        factors.append("App allows backup (android:allowBackup=true)")
        
    # 2. Code Analysis
    if code.get("suspicious_apis"):
        for api in code["suspicious_apis"]:
            if api.get("severity") == "High":
                score += 10
                factors.append(f"High risk API usage: {api['api']}")
                recommendations.add(f"Avoid or secure usage of {api['api']}.")
            elif api.get("severity") == "Medium":
                score += 5
                
    if code.get("malware_indicators"):
        for ind in code["malware_indicators"]:
            if ind.get("severity") == "Critical":
                score += 25
                factors.append(f"Critical malware indicator: {ind['why_flagged']}")
            elif ind.get("severity") == "High":
                score += 15
                factors.append(f"High malware indicator: {ind['why_flagged']}")
                
    # 3. Resource Analysis
    if resources.get("secrets"):
        score += 20
        factors.append(f"Found {len(resources['secrets'])} exposed secrets/keys in resources.")
        recommendations.add("Remove hardcoded API keys and secrets from assets/res.")
        
    # 4. Native Library Analysis
    if natives.get("suspicious_libraries"):
        score += 15
        factors.append(f"Found {len(natives['suspicious_libraries'])} suspicious native libraries.")
        
    # 5. YARA Matches
    for match in yara:
        if match.get("severity") == "Critical":
            score += 25
            factors.append(f"Critical YARA signature match: {match['rule_name']}")
        elif match.get("severity") == "High":
            score += 15
            factors.append(f"High YARA signature match: {match['rule_name']}")
        else:
            score += 5
            factors.append(f"YARA signature match: {match['rule_name']}")
            
    # 6. Misconfigurations
    if manifest.get("misconfigurations"):
        for m in manifest["misconfigurations"]:
            if m.get("severity") == "Critical": score += 10
            elif m.get("severity") == "High": score += 5
            elif m.get("severity") == "Medium": score += 2
            factors.append(m["title"])
            recommendations.add(m["recommendation"])
            
    # 7. Certificates
    if certs and isinstance(certs, list):
        for cert in certs:
            if cert.get("self_signed"):
                score += 15
                factors.append("APK is signed with a self-signed certificate.")
                recommendations.add("Sign the APK with a trusted CA certificate for production.")
                
    # 8. Obfuscation
    obfuscations = code.get("obfuscation_findings", [])
    if obfuscations:
        score += 10
        factors.append(f"Found {len(obfuscations)} highly obfuscated strings/payloads.")
        recommendations.add("Review high entropy strings to ensure they do not conceal malicious payloads.")
            
    # Cap score
    score = min(score, 100)
    
    # Determine level
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 40:
        level = "Medium"
    elif score >= 20:
        level = "Low"
    else:
        level = "Safe"
        
    return {
        "score": score,
        "level": level,
        "factors": factors,
        "recommendations": list(recommendations)
    }

def generate_iocs(metadata: Dict, code: Dict, resources: Dict, certs: List) -> Dict[str, Any]:
    """Generates an aggregated list of Indicators of Compromise (IOCs)."""
    iocs = {
        "hashes": [],
        "network": {
            "urls": code.get("network_indicators", {}).get("urls", []),
            "domains": code.get("network_indicators", {}).get("domains", []),
            "ipv4": code.get("network_indicators", {}).get("ipv4", []),
            "ipv6": code.get("network_indicators", {}).get("ipv6", []),
            "emails": code.get("network_indicators", {}).get("emails", [])
        },
        "certificates": [],
        "secrets": []
    }
    
    if metadata:
        if metadata.get("sha256"): iocs["hashes"].append({"type": "sha256", "value": metadata["sha256"]})
        if metadata.get("md5"): iocs["hashes"].append({"type": "md5", "value": metadata["md5"]})
        
    if certs and isinstance(certs, list):
        for c in certs:
            if c.get("sha1"): iocs["certificates"].append({"type": "sha1", "value": c["sha1"], "issuer": c.get("issuer")})
            if c.get("sha256"): iocs["certificates"].append({"type": "sha256", "value": c["sha256"], "issuer": c.get("issuer")})
            
    if resources.get("secrets"):
        for sec in resources["secrets"]:
            iocs["secrets"].append({"type": sec.get("type", "unknown"), "value": sec.get("value", "")})
            
    return iocs

def generate_ioc_csv(iocs: Dict, filepath: str) -> None:
    """Exports IOC dictionary to a flat CSV format."""
    import csv
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Type", "Value"])
        
        for h in iocs.get("hashes", []):
            writer.writerow(["Hash", h["type"], h["value"]])
            
        net = iocs.get("network", {})
        for url in net.get("urls", []): writer.writerow(["Network", "URL", url])
        for dom in net.get("domains", []): writer.writerow(["Network", "Domain", dom])
        for ip in net.get("ipv4", []): writer.writerow(["Network", "IPv4", ip])
        for email in net.get("emails", []): writer.writerow(["Network", "Email", email])
        
        for c in iocs.get("certificates", []):
            writer.writerow(["Certificate", c["type"], f"{c['value']} (Issuer: {c.get('issuer')})"])
            
        for s in iocs.get("secrets", []):
            writer.writerow(["Secret", s["type"], s["value"]])
