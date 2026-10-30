"""Phase 1: Certificate Scanner Engine"""
import hashlib
from typing import Dict, Any, List

try:
    from androguard.core.apk import APK
except ImportError:
    APK = None

def scan_certificates(apk_path: str) -> List[Dict[str, Any]]:
    findings = []
    
    if not APK:
        return [{"error": "Androguard not installed."}]
        
    try:
        apk_obj = APK(apk_path)
        certs = apk_obj.get_certificates()
        
        for cert in certs:
            cert_der = cert.dump()
            sha1 = hashlib.sha1(cert_der).hexdigest()
            sha256 = hashlib.sha256(cert_der).hexdigest()
            md5 = hashlib.md5(cert_der).hexdigest()
            
            # Use androguard's attributes
            issuer = cert.issuer.human_friendly if hasattr(cert, 'issuer') else "Unknown"
            subject = cert.subject.human_friendly if hasattr(cert, 'subject') else "Unknown"
            valid_from = cert.not_valid_before.isoformat() if hasattr(cert, 'not_valid_before') else "Unknown"
            valid_until = cert.not_valid_after.isoformat() if hasattr(cert, 'not_valid_after') else "Unknown"
            
            # Simple self-signed check
            is_self_signed = (issuer == subject)
            
            findings.append({
                "sha1": sha1,
                "sha256": sha256,
                "md5": md5,
                "issuer": issuer,
                "subject": subject,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "self_signed": is_self_signed
            })
    except Exception as e:
        findings.append({"error": str(e)})
        
    return findings
