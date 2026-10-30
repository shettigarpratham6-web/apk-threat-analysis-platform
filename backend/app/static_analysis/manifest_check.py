"""Phase 4: Manifest Analysis Engine"""
from typing import Dict, Any, List
from xml.etree import ElementTree as ET

# Permission Database
PERMISSIONS_DB = {
    "android.permission.SEND_SMS": {"severity": "Critical", "reason": "Allows sending SMS without user interaction.", "recommendation": "Verify whether SMS functionality is expected."},
    "android.permission.READ_SMS": {"severity": "High", "reason": "Allows reading of sensitive SMS messages.", "recommendation": "Check if SMS reading is required for core functionality."},
    "android.permission.RECEIVE_SMS": {"severity": "High", "reason": "Allows intercepting incoming SMS messages.", "recommendation": "Check if SMS receiving is required."},
    "android.permission.READ_CONTACTS": {"severity": "High", "reason": "Accesses personal contacts data.", "recommendation": "Ensure contact access has a clear privacy policy."},
    "android.permission.WRITE_CONTACTS": {"severity": "High", "reason": "Allows modifying user contacts.", "recommendation": "Ensure contact modification is intended."},
    "android.permission.ACCESS_FINE_LOCATION": {"severity": "High", "reason": "Accesses precise GPS location.", "recommendation": "Request only coarse location if precise isn't needed."},
    "android.permission.CAMERA": {"severity": "High", "reason": "Accesses the device camera.", "recommendation": "Ensure camera access is obvious to the user."},
    "android.permission.RECORD_AUDIO": {"severity": "High", "reason": "Accesses the microphone to record audio.", "recommendation": "Ensure audio recording is obvious to the user."},
    "android.permission.SYSTEM_ALERT_WINDOW": {"severity": "Critical", "reason": "Allows drawing over other apps (often used for overlay attacks).", "recommendation": "Remove unless building a specialized UI tool."},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"severity": "Critical", "reason": "Allows the app to install other packages.", "recommendation": "Remove unless building an app store."},
    "android.permission.INTERNET": {"severity": "Normal", "reason": "Allows network access.", "recommendation": "Standard permission, but check for data exfiltration."},
    "android.permission.ACCESS_NETWORK_STATE": {"severity": "Normal", "reason": "Allows checking network connectivity.", "recommendation": "Standard permission."},
}

def analyze_manifest(apk_obj: Any) -> Dict[str, Any]:
    """
    Parses AndroidManifest.xml from Androguard APK object.
    Extracts metadata, components, security flags, and classifies permissions.
    """
    manifest_info = {
        "metadata": {},
        "components": {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": []
        },
        "security_flags": {},
        "misconfigurations": [],
        "permissions": []
    }
    
    try:
        manifest_info["metadata"] = {
            "package_name": apk_obj.get_package(),
            "version_name": apk_obj.get_androidversion_name(),
            "version_code": apk_obj.get_androidversion_code(),
            "min_sdk": apk_obj.get_min_sdk_version(),
            "target_sdk": apk_obj.get_target_sdk_version(),
            "compile_sdk": getattr(apk_obj, 'get_compile_sdk_version', lambda: None)()
        }
    except Exception as e:
        manifest_info["metadata"]["error"] = str(e)

    # Permissions
    try:
        requested_perms = apk_obj.get_permissions() or []
        for perm in requested_perms:
            perm_str = str(perm)
            perm_info = PERMISSIONS_DB.get(perm_str, {
                "severity": "Low" if perm_str.startswith("android.permission") else "Unknown",
                "reason": "Standard or custom permission.",
                "recommendation": "Review if necessary."
            })
            
            # Determine Category
            category = "Dangerous" if perm_info["severity"] in ["High", "Critical"] else "Normal"
            if "SYSTEM_ALERT" in perm_str or "INSTALL_PACKAGES" in perm_str:
                category = "Special"
                
            manifest_info["permissions"].append({
                "name": perm_str,
                "category": category,
                "severity": perm_info["severity"],
                "reason": perm_info["reason"],
                "recommendation": perm_info["recommendation"]
            })
    except Exception:
        pass

    # Extract components & security flags from raw XML
    try:
        xml_bytes = apk_obj.get_android_manifest_xml().get_xml()
        root = ET.fromstring(xml_bytes)
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        
        app_node = root.find("application")
        if app_node is not None:
            # Security flags
            allow_backup = app_node.attrib.get(f"{{{ns['android']}}}allowBackup", "true") == "true"
            debuggable = app_node.attrib.get(f"{{{ns['android']}}}debuggable", "false") == "true"
            cleartext = app_node.attrib.get(f"{{{ns['android']}}}usesCleartextTraffic", "false") == "true"
            net_sec = app_node.attrib.get(f"{{{ns['android']}}}networkSecurityConfig", None)
            shared_user = root.attrib.get(f"{{{ns['android']}}}sharedUserId", None)
            
            manifest_info["security_flags"] = {
                "debuggable": debuggable,
                "allowBackup": allow_backup,
                "usesCleartextTraffic": cleartext,
                "networkSecurityConfig": net_sec is not None,
                "sharedUserId": shared_user,
                "taskAffinity": app_node.attrib.get(f"{{{ns['android']}}}taskAffinity", None)
            }
            
            # Audit Misconfigurations
            if allow_backup:
                manifest_info["misconfigurations"].append({"title": "AllowBackup Enabled", "severity": "Medium", "description": "App data can be backed up and restored, which might lead to data leakage.", "recommendation": "Set android:allowBackup='false'."})
            if debuggable:
                manifest_info["misconfigurations"].append({"title": "App is Debuggable", "severity": "Critical", "description": "Attackers can attach a debugger and extract sensitive runtime data.", "recommendation": "Set android:debuggable='false' for production releases."})
            if cleartext:
                manifest_info["misconfigurations"].append({"title": "Cleartext Traffic Allowed", "severity": "High", "description": "App can communicate over unencrypted HTTP, risking MITM attacks.", "recommendation": "Set android:usesCleartextTraffic='false' and enforce HTTPS."})
            if not net_sec:
                manifest_info["misconfigurations"].append({"title": "Missing Network Security Config", "severity": "Low", "description": "App does not define a custom network security policy.", "recommendation": "Implement a network security config to enforce Certificate Pinning."})
            if shared_user:
                manifest_info["misconfigurations"].append({"title": "Shared User ID Configured", "severity": "Medium", "description": "App shares its process/sandbox with other apps.", "recommendation": "Remove sharedUserId to maintain sandbox isolation."})
            
            # Components
            for comp_type, tag in [("activities", "activity"), ("services", "service"), 
                                   ("receivers", "receiver"), ("providers", "provider")]:
                for comp in app_node.findall(tag):
                    name = comp.attrib.get(f"{{{ns['android']}}}name", "Unknown")
                    exported = comp.attrib.get(f"{{{ns['android']}}}exported", None)
                    enabled = comp.attrib.get(f"{{{ns['android']}}}enabled", "true") == "true"
                    perms_attached = comp.attrib.get(f"{{{ns['android']}}}permission", None)
                    
                    intent_filters = []
                    for intent in comp.findall("intent-filter"):
                        for action in intent.findall("action"):
                            action_name = action.attrib.get(f"{{{ns['android']}}}name")
                            if action_name:
                                intent_filters.append(action_name)
                    
                    if exported is None:
                        # Auto-exported if it has intent filters in older Android versions
                        exported = len(intent_filters) > 0
                    else:
                        exported = exported == "true"
                        
                    if exported:
                        manifest_info["misconfigurations"].append({
                            "title": f"Exported {comp_type[:-1].capitalize()}",
                            "severity": "Medium",
                            "description": f"The component '{name}' is exposed to other apps.",
                            "recommendation": "Set android:exported='false' unless exposure is strictly required. Enforce permissions if exposed."
                        })
                        
                    manifest_info["components"][comp_type].append({
                        "name": name,
                        "exported": exported,
                        "enabled": enabled,
                        "permissions_attached": perms_attached,
                        "intent_filters": intent_filters
                    })
    except Exception as e:
        manifest_info["security_flags"]["error"] = f"Failed to parse XML: {str(e)}"
        
    return manifest_info
