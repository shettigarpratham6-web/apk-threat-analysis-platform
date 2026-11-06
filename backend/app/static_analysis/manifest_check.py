"""Phase 4: Manifest Analysis Engine"""
from typing import Dict, Any, List
from xml.etree import ElementTree as ET

# Permission Database with Forensic Rationales and Threat Context
PERMISSIONS_DB = {
    # Telephony & Messaging
    "android.permission.SEND_SMS": {
        "severity": "Critical",
        "category": "Toll Fraud & Exfiltration",
        "reason": "Allows sending SMS messages in the background without user interaction or confirmation.",
        "attack_vector": "Malware frequently abuses this to subscribe users to premium SMS rate services or leak sensitive data.",
        "recommendation": "Verify whether SMS transmission is an essential business feature; prefer user-prompted SMS intents."
    },
    "android.permission.READ_SMS": {
        "severity": "High",
        "category": "Credential Harvesting",
        "reason": "Allows reading incoming and stored SMS messages including one-time passwords (OTPs) and 2FA authentication codes.",
        "attack_vector": "Used by banking Trojans to bypass SMS-based multi-factor authentication.",
        "recommendation": "Use SMS Retriever API or User Consent API instead of requesting broad READ_SMS."
    },
    "android.permission.RECEIVE_SMS": {
        "severity": "High",
        "category": "Interception",
        "reason": "Allows monitoring and intercepting incoming SMS broadcasts before user notification.",
        "attack_vector": "Enables silent theft and suppression of transaction verification codes.",
        "recommendation": "Migrate to Google Play Services SMS Retriever API."
    },
    "android.permission.CALL_PHONE": {
        "severity": "Critical",
        "category": "Toll Fraud",
        "reason": "Initiates outgoing telephone calls directly without navigating through dialer UI.",
        "attack_vector": "Malware can call premium numbers to incur substantial charges on the user's phone bill.",
        "recommendation": "Use ACTION_DIAL intent so user explicitly initiates calls."
    },
    "android.permission.READ_PHONE_STATE": {
        "severity": "High",
        "category": "Device Fingerprinting",
        "reason": "Allows accessing cellular state, carrier info, phone number, and unique hardware identifiers (IMEI/IMSI).",
        "attack_vector": "Enables persistent device tracking and tracking across app installations.",
        "recommendation": "Avoid querying phone state for app identity; generate an ephemeral UUID instead."
    },
    "android.permission.READ_CALL_LOG": {
        "severity": "High",
        "category": "Surveillance",
        "reason": "Exposes incoming/outgoing call records, contact numbers, and call durations.",
        "attack_vector": "Harvests sensitive communication metadata for stalking or spear-phishing campaigns.",
        "recommendation": "Remove permission unless app is an authorized default dialer."
    },
    "android.permission.WRITE_CALL_LOG": {
        "severity": "High",
        "category": "Anti-Forensics",
        "reason": "Allows altering or deleting entries from the device call history log.",
        "attack_vector": "Malware erases records of unauthorized outgoing calls to hide activity from device owners.",
        "recommendation": "Do not request call log modification permissions."
    },

    # Contacts & Personal Data
    "android.permission.READ_CONTACTS": {
        "severity": "High",
        "category": "Privacy Violation",
        "reason": "Allows reading contact names, phone numbers, and email addresses stored on the device.",
        "attack_vector": "Spyware exfiltrates entire contact books to command-and-control servers for spam distribution.",
        "recommendation": "Ensure contact access has a clear privacy rationale; consider Android Contact Picker intent."
    },
    "android.permission.WRITE_CONTACTS": {
        "severity": "High",
        "category": "Data Tampering",
        "reason": "Allows modifying, adding, or deleting contact records.",
        "attack_vector": "Malicious apps can inject fraudulent contact entries or corrupt existing address books.",
        "recommendation": "Verify necessity of modifying address book records."
    },

    # Geolocation Tracking
    "android.permission.ACCESS_FINE_LOCATION": {
        "severity": "High",
        "category": "Surveillance",
        "reason": "Accesses precise GPS and GNSS coordinates (within meters) of the physical device.",
        "attack_vector": "Allows stalkerware and location tracking SDKs to map user movements in real time.",
        "recommendation": "Request ACCESS_COARSE_LOCATION if approximate position is sufficient."
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "severity": "Medium",
        "category": "Geo-Tracking",
        "reason": "Estimates user position using cellular network towers and Wi-Fi access points.",
        "attack_vector": "Enables city-level location profiling without GPS activation.",
        "recommendation": "Request only when active location context is required by the user flow."
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "severity": "High",
        "category": "Continuous Surveillance",
        "reason": "Allows tracking user geolocation constantly in the background even when app is closed.",
        "attack_vector": "Provides continuous spatial intelligence without user awareness.",
        "recommendation": "Prompt user with clear in-app disclosure before requesting background tracking."
    },

    # Hardware & Audio/Video
    "android.permission.CAMERA": {
        "severity": "High",
        "category": "Surveillance / Spyware",
        "reason": "Accesses the camera sensor to capture still photographs and record video.",
        "attack_vector": "Covert camera activation for espionage or blackmail.",
        "recommendation": "Display an active viewfinder preview and notification whenever the camera is operating."
    },
    "android.permission.RECORD_AUDIO": {
        "severity": "High",
        "category": "Audio Surveillance",
        "reason": "Accesses the microphone to record surrounding ambient audio and phone conversations.",
        "attack_vector": "Eavesdropping malware records private discussions and exfiltrates audio snippets.",
        "recommendation": "Provide explicit visual recording indicators."
    },

    # System & Execution Control
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "severity": "Critical",
        "category": "UI Overlay Hijacking",
        "reason": "Allows drawing floating overlay windows on top of any active third-party application.",
        "attack_vector": "Phishing overlay attacks: displays fake login forms over banking or crypto apps to steal credentials.",
        "recommendation": "Remove unless building a genuine accessibility utility or system HUD."
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "severity": "Critical",
        "category": "Dropper / Secondary Payload",
        "reason": "Allows the application to initiate installation of new APK packages from local storage.",
        "attack_vector": "Acts as a malicious dropper, downloading and launching additional trojans or ransomware payloads.",
        "recommendation": "Remove unless developing an official app marketplace."
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "severity": "High",
        "category": "Persistence",
        "reason": "Allows starting broadcast receivers and background services immediately upon device startup.",
        "attack_vector": "Malware achieves persistent survival across device restarts without user launching the app.",
        "recommendation": "Avoid automatic boot execution; trigger background tasks via WorkManager or push events."
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "severity": "Critical",
        "category": "Privilege Escalation",
        "reason": "Grants complete accessibility rights to inspect on-screen UI text, monitor keypresses, and simulate taps.",
        "attack_vector": "Accessibility Trojans hijack device control, steal MFA codes from authenticator apps, and auto-grant permissions.",
        "recommendation": "Strictly reserved for verified assistive technologies for disabled users."
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "severity": "Critical",
        "category": "Device Takeover",
        "reason": "Enables device administrator authority, granting lock-out, password reset, and remote data wipe capabilities.",
        "attack_vector": "Ransomware locks the screen with admin privileges and blocks uninstallation.",
        "recommendation": "Ensure device admin usage complies with Enterprise Mobility Management standards."
    },
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
        "severity": "Medium",
        "category": "Evasion / Persistence",
        "reason": "Exempts app from OS Doze mode and background power throttling.",
        "attack_vector": "Allows persistent background C2 communication without being suspended by Android OS.",
        "recommendation": "Utilize modern JobScheduler/WorkManager primitives instead."
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "severity": "High",
        "category": "Reconnaissance",
        "reason": "Allows querying and enumerating all installed applications on the target device.",
        "attack_vector": "Financial malware scouts for targeted banking and crypto apps before triggering overlay attacks.",
        "recommendation": "Specify explicit <queries> elements in the manifest instead of querying all packages."
    },

    # Storage Access
    "android.permission.READ_EXTERNAL_STORAGE": {
        "severity": "High",
        "category": "Data Exfiltration",
        "reason": "Allows reading files from shared external storage including photos, documents, and other apps' shared caches.",
        "attack_vector": "Unauthorized harvesting of sensitive documents, images, and backup files.",
        "recommendation": "Adopt Android Scoped Storage model."
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "severity": "High",
        "category": "Storage Tampering",
        "reason": "Allows creating, altering, and deleting files across external storage volumes.",
        "attack_vector": "Ransomware encrypts user files; trojans overwrite legitimate media files.",
        "recommendation": "Use scoped app-specific directory (Context.getExternalFilesDir)."
    },

    # Network & Standard
    "android.permission.INTERNET": {
        "severity": "Normal",
        "category": "Network Communication",
        "reason": "Allows opening network sockets to communicate over the Internet.",
        "attack_vector": "Enables exfiltration of gathered intelligence and connection to C2 servers.",
        "recommendation": "Enforce TLS 1.3 encryption and implement certificate pinning for critical backend endpoints."
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "severity": "Normal",
        "category": "Network Status",
        "reason": "Allows checking current network connectivity status (Wi-Fi, cellular, roaming).",
        "attack_vector": "Malware pauses heavy exfiltration while on metered cellular data to avoid alerting the victim.",
        "recommendation": "Standard permission; monitor for correlation with sudden data transfer spikes."
    },
    "android.permission.CHANGE_WIFI_STATE": {
        "severity": "Medium",
        "category": "Network Manipulation",
        "reason": "Allows connecting, disconnecting, and modifying saved Wi-Fi networks.",
        "attack_vector": "Can force connection to rogue evil-twin Wi-Fi access points.",
        "recommendation": "Remove unless managing dedicated IoT hardware connections."
    },
    "android.permission.FOREGROUND_SERVICE": {
        "severity": "Normal",
        "category": "Background Service",
        "reason": "Allows running ongoing foreground services with user-visible notifications.",
        "attack_vector": "Can be disguised with trivial notification icons while executing covert operations.",
        "recommendation": "Ensure foreground service notification provides clear, accurate description of active service."
    },
    "android.permission.WAKE_LOCK": {
        "severity": "Normal",
        "category": "Power State",
        "reason": "Prevents the device CPU and screen from entering low-power sleep states.",
        "attack_vector": "Cryptominers or background botnets keep CPU running continuously.",
        "recommendation": "Ensure wake locks are acquired with timeouts and released promptly."
    },
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
            category = perm_info.get("category")
            if not category:
                category = "Dangerous" if perm_info["severity"] in ["High", "Critical"] else "Normal"
                if "SYSTEM_ALERT" in perm_str or "INSTALL_PACKAGES" in perm_str:
                    category = "Special"
                
            manifest_info["permissions"].append({
                "name": perm_str,
                "category": category,
                "severity": perm_info["severity"],
                "reason": perm_info["reason"],
                "recommendation": perm_info["recommendation"],
                "attack_vector": perm_info.get("attack_vector", "Potential misuse by untrusted components"),
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
