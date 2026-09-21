"""Module for extracting Android Manifest permissions, package metadata, and SDK details."""

from typing import Any, Dict, List

DANGEROUS_PERMISSIONS = {
    # Calendar
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    # Camera
    "android.permission.CAMERA",
    # Contacts
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    # Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_MEDIA_LOCATION",
    # Microphone
    "android.permission.RECORD_AUDIO",
    # Phone
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ACCEPT_HANDOVER",
    # Sensors
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    # SMS
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    # Special / High-risk Permissions
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}


def analyze_manifest(apk: Any) -> Dict[str, Any]:
    """
    Extracts manifest details, package info, permissions, and SDK versions from an APK object.

    :param apk: Parsed Androguard APK instance.
    :return: Structured dictionary containing manifest metrics.
    """
    package_name = apk.get_package()
    main_activity = apk.get_main_activity()
    min_sdk = apk.get_min_sdk_version()
    target_sdk = apk.get_target_sdk_version()

    # Extracted requested permissions
    raw_requested = apk.get_permissions() or []
    requested_permissions: List[str] = [str(p) for p in raw_requested]

    # Extracted declared permissions
    raw_declared = apk.get_declared_permissions() or []
    declared_permissions: List[str] = [str(p) for p in raw_declared]

    # Identify dangerous permissions
    details_permissions = getattr(apk, "get_details_permissions", lambda: {})() or {}
    dangerous_permissions: List[str] = []

    for perm in requested_permissions:
        is_dangerous = perm in DANGEROUS_PERMISSIONS

        if not is_dangerous and perm in details_permissions:
            perm_meta = details_permissions[perm]
            protection_level = ""
            if isinstance(perm_meta, dict):
                protection_level = str(perm_meta.get("protectionLevel", "")).lower()
            elif isinstance(perm_meta, (list, tuple)) and len(perm_meta) > 0:
                protection_level = str(perm_meta[0]).lower()

            if "dangerous" in protection_level:
                is_dangerous = True

        if is_dangerous:
            dangerous_permissions.append(perm)

    # Deduplicate while preserving order
    dangerous_permissions = list(dict.fromkeys(dangerous_permissions))

    return {
        "package_name": package_name,
        "main_activity": main_activity,
        "permissions": {
            "requested": requested_permissions,
            "dangerous": dangerous_permissions,
            "declared": declared_permissions,
        },
        "sdk": {
            "min_sdk_version": str(min_sdk) if min_sdk is not None else None,
            "target_sdk_version": str(target_sdk) if target_sdk is not None else None,
        },
    }
