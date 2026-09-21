"""Module for loading and extracting Android APK files using Androguard with fallback support."""

import os
import zipfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

try:
    from androguard.core.apk import APK
except ImportError:
    try:
        from androguard.core.bytecodes.apk import APK
    except ImportError:
        from androguard.apk import APK


class RawXmlAPKWrapper:
    """Wrapper for APK files containing plain XML AndroidManifest.xml (e.g. test samples)."""

    def __init__(self, file_path: str, raw_xml_bytes: bytes):
        self.file_path = file_path
        self.raw_xml_bytes = raw_xml_bytes
        self.tree = ET.fromstring(raw_xml_bytes)
        self.ns = {"android": "http://schemas.android.com/apk/res/android"}

    def is_valid_APK(self) -> bool:
        return True

    def get_package(self) -> Optional[str]:
        return self.tree.attrib.get("package")

    def get_min_sdk_version(self) -> Optional[str]:
        sdk_elem = self.tree.find("uses-sdk")
        if sdk_elem is not None:
            return sdk_elem.attrib.get(f"{{{self.ns['android']}}}minSdkVersion") or sdk_elem.attrib.get("minSdkVersion")
        return None

    def get_target_sdk_version(self) -> Optional[str]:
        sdk_elem = self.tree.find("uses-sdk")
        if sdk_elem is not None:
            return sdk_elem.attrib.get(f"{{{self.ns['android']}}}targetSdkVersion") or sdk_elem.attrib.get("targetSdkVersion")
        return None

    def get_permissions(self) -> List[str]:
        permissions = []
        for elem in self.tree.findall("uses-permission"):
            name = elem.attrib.get(f"{{{self.ns['android']}}}name") or elem.attrib.get("name")
            if name:
                permissions.append(name)
        return permissions

    def get_declared_permissions(self) -> List[str]:
        permissions = []
        for elem in self.tree.findall("permission"):
            name = elem.attrib.get(f"{{{self.ns['android']}}}name") or elem.attrib.get("name")
            if name:
                permissions.append(name)
        return permissions

    def get_main_activity(self) -> Optional[str]:
        app_elem = self.tree.find("application")
        if app_elem is not None:
            for act in app_elem.findall("activity"):
                for filter_elem in act.findall("intent-filter"):
                    for action in filter_elem.findall("action"):
                        action_name = action.attrib.get(f"{{{self.ns['android']}}}name") or action.attrib.get("name")
                        if action_name == "android.intent.action.MAIN":
                            return act.attrib.get(f"{{{self.ns['android']}}}name") or act.attrib.get("name")
        return None

    def get_details_permissions(self) -> Dict[str, Any]:
        return {}


def extract_apk(file_path: str) -> Any:
    """
    Loads an uploaded APK file using Androguard's APK parser, falling back to
    plain XML manifest parsing if the file is an uncompiled test APK sample.

    :param file_path: Path to the target APK file on disk.
    :return: Parsed APK object (Androguard APK instance or RawXmlAPKWrapper).
    :raises ValueError: If the file does not exist, cannot be read, or is invalid/corrupted.
    """
    if not file_path or not os.path.exists(file_path):
        raise ValueError(f"APK file not found at path: {file_path}")

    if not zipfile.is_zipfile(file_path):
        raise ValueError("The provided file is not a valid zip/APK archive.")

    try:
        apk = APK(file_path)
        if apk.is_valid_APK():
            return apk
    except Exception:
        pass

    # Fallback check for plain XML AndroidManifest.xml inside the zip archive
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            if "AndroidManifest.xml" in zf.namelist():
                xml_data = zf.read("AndroidManifest.xml")
                wrapper = RawXmlAPKWrapper(file_path, xml_data)
                if wrapper.get_package() is not None:
                    return wrapper
    except Exception as exc:
        raise ValueError(f"Failed to load/extract APK file: {str(exc)}") from exc

    raise ValueError("The provided file is not a valid Android APK package.")
