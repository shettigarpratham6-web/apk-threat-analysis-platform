"""Configuration constants for Android Emulator sandbox management."""

import os
from pathlib import Path

# Path to Android SDK emulator binary (read from env var with fallback)
ANDROID_EMULATOR_PATH = os.getenv(
    "ANDROID_EMULATOR_PATH",
    os.path.join(
        os.getenv("ANDROID_HOME", os.path.expanduser("~") + "/AppData/Local/Android/Sdk"),
        "emulator",
        "emulator.exe" if os.name == "nt" else "emulator",
    ),
)

# Path to ADB binary
ADB_PATH = os.getenv(
    "ADB_PATH",
    os.path.join(
        os.getenv("ANDROID_HOME", os.path.expanduser("~") + "/AppData/Local/Android/Sdk"),
        "platform-tools",
        "adb.exe" if os.name == "nt" else "adb",
    ),
)

# Target Android Virtual Device (AVD) Name
AVD_NAME = os.getenv("AVD_NAME", "threat_sandbox_avd")

# Target Android API Level
API_LEVEL = int(os.getenv("API_LEVEL", "33"))

# Headless mode flag (run emulator without GUI window)
HEADLESS_MODE = os.getenv("HEADLESS_MODE", "true").lower() in ("true", "1", "yes")

# Snapshot name for clean environment resets
SNAPSHOT_NAME = os.getenv("SNAPSHOT_NAME", "clean_state")

# Timeout in seconds to wait for emulator boot
BOOT_TIMEOUT = int(os.getenv("BOOT_TIMEOUT", "60"))
