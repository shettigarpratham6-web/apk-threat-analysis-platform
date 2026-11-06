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

    def get_active_device_serial(self) -> Optional[str]:
        """Detects the first online/ready ADB device or emulator serial."""
        try:
            res = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, check=False, timeout=5)
            output = res.stdout if res.returncode == 0 else ""
            lines = [l.strip() for l in output.strip().splitlines() if l.strip() and not l.startswith("*") and not l.startswith("List of")]
            for line in lines:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    return parts[0]
        except Exception as exc:
            logger.debug(f"Error querying ADB devices: {exc}")
        return None

    def wait_for_device(self, timeout: int = 20) -> Optional[str]:
        """Polls until an active device is ready, attempting reconnect if needed."""
        start = time.time()
        while time.time() - start < timeout:
            serial = self.get_active_device_serial()
            if serial:
                # Check boot completion
                try:
                    chk = subprocess.run(
                        [self.adb_path, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5,
                    )
                    if chk.stdout.strip() == "1":
                        return serial
                except Exception:
                    pass
            # Try adb reconnect if no device seen after 4 seconds
            if time.time() - start > 4:
                try:
                    subprocess.run([self.adb_path, "reconnect"], capture_output=True, text=True, check=False, timeout=3)
                except Exception:
                    pass
            time.sleep(1.5)
        return self.get_active_device_serial()

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

    def install_apk(self, apk_path: str, max_retries: int = 3) -> str:
        """
        Installs an APK onto the sandboxed emulator via 'adb install -r' with automatic device detection and retry.

        :param apk_path: Path to the APK file on disk.
        :param max_retries: Number of installation attempts before failing.
        :return: ADB output string on success.
        :raises RuntimeError: If ADB installation fails or output does not indicate 'Success'.
        """
        if not os.path.exists(apk_path):
            raise RuntimeError(f"Cannot install APK, file not found at path: {apk_path}")

        # Ensure device is ready
        serial = self.wait_for_device(timeout=15)
        last_error = ""

        for attempt in range(1, max_retries + 1):
            cmd = [self.adb_path]
            if serial:
                cmd.extend(["-s", serial])
            cmd.extend(["install", "-r", apk_path])

            logger.info(f"Installing APK onto emulator (attempt {attempt}/{max_retries}): {' '.join(cmd)}")
            print(f"[DYNAMIC LOG] Installing APK (attempt {attempt}/{max_retries}): {apk_path}")

            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=90,
                )
                output = (res.stdout or "") + "\n" + (res.stderr or "")

                if "Success" in output or res.returncode == 0:
                    logger.info(f"APK installed successfully: {apk_path}")
                    print(f"[DYNAMIC LOG] APK install SUCCESS: {apk_path}")
                    return output
                else:
                    last_error = f"ADB install failed (code {res.returncode}): {output.strip()}"
                    logger.warning(f"Install attempt {attempt} failed: {output.strip()}")

                    # If device not found or offline, wait and reconnect before retrying
                    if "no devices" in output.lower() or "offline" in output.lower():
                        logger.info("Attempting ADB reconnect and waiting for device...")
                        try:
                            subprocess.run([self.adb_path, "reconnect"], capture_output=True, text=True, check=False, timeout=5)
                        except Exception:
                            pass
                        serial = self.wait_for_device(timeout=10)

                    time.sleep(2)
            except subprocess.TimeoutExpired:
                last_error = f"ADB install timed out after 90 seconds on attempt {attempt}"
                logger.warning(last_error)
                time.sleep(2)
            except Exception as exc:
                last_error = f"Exception occurred while installing APK '{apk_path}': {str(exc)}"
                logger.warning(last_error)
                time.sleep(2)

        err_msg = last_error or f"Failed to install APK '{apk_path}' after {max_retries} attempts."
        logger.error(err_msg)
        print(f"[DYNAMIC ERROR] {err_msg}")
        raise RuntimeError(err_msg)

    def launch_apk(self, package_name: str) -> str:
        """
        Launches the installed app using ADB monkey launcher.

        :param package_name: Package name of the app to launch.
        :return: ADB command output.
        :raises RuntimeError: If ADB launch command fails.
        """
        serial = self.get_active_device_serial()
        cmd = [self.adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend([
            "shell",
            "monkey",
            "-p",
            package_name,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ])
        logger.info(f"Launching package '{package_name}' via ADB monkey: {' '.join(cmd)}")
        print(f"[DYNAMIC LOG] Launching app package '{package_name}' in emulator...")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
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
        serial = self.get_active_device_serial()
        cmd = [self.adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(["uninstall", package_name])
        logger.info(f"Uninstalling package '{package_name}'...")
        print(f"[DYNAMIC LOG] Cleaning up app '{package_name}'...")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            if res.returncode == 0 or "Success" in (res.stdout or ""):
                logger.info(f"Package '{package_name}' uninstalled cleanly.")
            else:
                logger.warning(f"Uninstall output for '{package_name}': {res.stdout or res.stderr}")
        except Exception as exc:
            logger.warning(f"Non-fatal exception during uninstall of '{package_name}': {exc}")
