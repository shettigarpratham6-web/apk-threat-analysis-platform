"""Compiled regex patterns and suspicious API targets for static code analysis."""

import re

# Regex matching HTTP and HTTPS URLs
URL_PATTERN = re.compile(
    r"https?://(?:[a-zA-Z0-9$-_@.&+!*'(#),]|%[0-9a-fA-F]{2})+",
    re.IGNORECASE
)

# Regex matching IPv4 addresses
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# List of suspicious and sensitive Android/Java API signatures
SUSPICIOUS_API_LIST = [
    "Runtime.exec",
    "ProcessBuilder",
    "DexClassLoader",
    "PathClassLoader",
    "InMemoryDexClassLoader",
    "sendTextMessage",
    "getDeviceId",
    "getSubscriberId",
    "getSimSerialNumber",
    "getImei",
    "HttpURLConnection",
    "HttpsURLConnection",
    "Socket",
    "URL.openConnection",
    "Class.forName",
    "getMethod",
    "getDeclaredMethod",
    "Cipher.getInstance",
    "SecretKeySpec",
]
