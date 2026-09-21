"""Module for installing, launching, and uninstalling APKs in the sandboxed Android emulator."""

import logging
import os
import subprocess
import time
from typing import Optional

from backend.app.static_analysis.apk_loader import extract_apk
from sandbox.emulator_config import ADB_PATH

logger = logging.getLogger("apk_runner")


class ApkRunner:
    """Handles APK installation, package resolution, app launching, and cleanup via ADB."""

    def __init__(self, adb_path: str = ADB_PATH):
        self.adb_path = adb_path

    def get_package_name(self, apk_path: str) -> str:
        """
        Extracts the package name from the target APK using static_analysis apk_loader.

        :param apk_path: Path to the APK file on disk.
        :return: Package name string (e.g. 'com.example.app').
        :raises ValueError: If APK is invalid or package name cannot be extracted.
        """
        if not os.path.exists(apk_path):
            raise ValueError(f"APK file not found at path: {apk_path}")

        apk_obj = extract_apk(apk_path)
        pkg_name = apk_obj.get_package()
        if not pkg_name:
            raise ValueError(f"Could not extract package name from APK: {apk_path}")

        return str(pkg_name)

    def install_apk(self, apk_path: str) -> str:
        """
        Installs an APK onto the sandboxed emulator via 'adb install -r'.

        :param apk_path: Path to the APK file on disk.
        :return: ADB output string on success.
        :raises RuntimeError: If ADB installation fails or output does not indicate 'Success'.
        """
        if not os.path.exists(apk_path):
            raise RuntimeError(f"Cannot install APK, file not found at path: {apk_path}")

        cmd = [self.adb_path, "install", "-r", apk_path]
        logger.info(f"Installing APK onto emulator: {' '.join(cmd)}")
        print(f"[DYNAMIC LOG] Installing APK: {apk_path}")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            output = (res.stdout or "") + "\n" + (res.stderr or "")

            if "Success" in output or res.returncode == 0:
                logger.info(f"APK installed successfully: {apk_path}")
                print(f"[DYNAMIC LOG] APK install SUCCESS: {apk_path}")
                return output
            else:
                err_msg = f"ADB install failed (code {res.returncode}): {output.strip()}"
                logger.error(err_msg)
                print(f"[DYNAMIC ERROR] {err_msg}")
                raise RuntimeError(err_msg)
        except Exception as exc:
            if isinstance(exc, RuntimeError):
                raise
            err_msg = f"Exception occurred while installing APK '{apk_path}': {str(exc)}"
            logger.error(err_msg)
            print(f"[DYNAMIC ERROR] {err_msg}")
            raise RuntimeError(err_msg) from exc

    def launch_apk(self, package_name: str) -> str:
        """
        Launches the installed app using ADB monkey launcher.

        :param package_name: Package name of the app to launch.
        :return: ADB command output.
        :raises RuntimeError: If ADB launch command fails.
        """
        cmd = [
            self.adb_path,
            "shell",
            "monkey",
            "-p",
            package_name,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ]
        logger.info(f"Launching package '{package_name}' via ADB monkey...")
        print(f"[DYNAMIC LOG] Launching app package '{package_name}' in emulator...")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            output = (res.stdout or "") + "\n" + (res.stderr or "")

            if res.returncode == 0 or "Events injected: 1" in output or "No activities found" not in output:
                logger.info(f"App package '{package_name}' launched successfully.")
                print(f"[DYNAMIC LOG] App '{package_name}' launched successfully.")
                return output
            else:
                err_msg = f"ADB launch failed for package '{package_name}': {output.strip()}"
                logger.error(err_msg)
                print(f"[DYNAMIC ERROR] {err_msg}")
                raise RuntimeError(err_msg)
        except Exception as exc:
            if isinstance(exc, RuntimeError):
                raise
            err_msg = f"Exception occurred launching package '{package_name}': {str(exc)}"
            logger.error(err_msg)
            print(f"[DYNAMIC ERROR] {err_msg}")
            raise RuntimeError(err_msg) from exc

    def uninstall_apk(self, package_name: str) -> None:
        """
        Uninstalls the app package from the emulator for cleanup.
        Failures are logged without raising exceptions.
        """
        cmd = [self.adb_path, "uninstall", package_name]
        logger.info(f"Uninstalling package '{package_name}'...")
        print(f"[DYNAMIC LOG] Cleaning up app '{package_name}'...")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 or "Success" in (res.stdout or ""):
                logger.info(f"Package '{package_name}' uninstalled cleanly.")
            else:
                logger.warning(f"Uninstall output for '{package_name}': {res.stdout or res.stderr}")
        except Exception as exc:
            logger.warning(f"Non-fatal exception during uninstall of '{package_name}': {exc}")
