"""Module for managing the lifecycle of the Android Emulator sandbox environment."""

import logging
import os
import subprocess
import time
from typing import Optional

from sandbox.emulator_config import (
    ADB_PATH,
    ANDROID_EMULATOR_PATH,
    AVD_NAME,
    BOOT_TIMEOUT,
    HEADLESS_MODE,
    SNAPSHOT_NAME,
)

logger = logging.getLogger("sandbox_manager")


class SandboxManager:
    """Manages spawning, readiness polling, snapshot restoring, and stopping the Android Emulator."""

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.emulator_path = ANDROID_EMULATOR_PATH
        self.adb_path = ADB_PATH
        self.avd_name = AVD_NAME
        self.snapshot_name = SNAPSHOT_NAME
        self.headless = HEADLESS_MODE

    def start_emulator(self) -> None:
        """
        Launches the Android emulator process asynchronously using Popen.

        :raises RuntimeError: If launching the emulator process fails.
        """
        if self.process is not None and self.process.poll() is None:
            logger.info("Emulator process is already running.")
            print("[SANDBOX LOG] Emulator process is already active.")
            return

        cmd = [self.emulator_path, "-avd", self.avd_name, "-no-snapshot-save"]
        if self.headless:
            cmd.append("-no-window")

        logger.info(f"Launching Android emulator: {' '.join(cmd)}")
        print(f"[SANDBOX LOG] Launching emulator: {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
        except Exception as exc:
            err_msg = (
                f"Failed to start emulator using path '{self.emulator_path}'. "
                f"Ensure Android SDK is installed and ANDROID_EMULATOR_PATH is correct. Error: {str(exc)}"
            )
            logger.error(err_msg)
            print(f"[SANDBOX ERROR] {err_msg}")
            raise RuntimeError(err_msg) from exc

    def wait_until_ready(self, timeout: int = BOOT_TIMEOUT) -> bool:
        """
        Polls ADB devices until the emulator is reported as ready ('device').

        :param timeout: Seconds to wait before raising TimeoutError.
        :return: True if ready.
        :raises TimeoutError: If emulator does not reach ready state within timeout.
        """
        start_time = time.time()
        logger.info(f"Waiting for emulator readiness via ADB (timeout={timeout}s)...")
        print(f"[SANDBOX LOG] Polling ADB status for emulator readiness (timeout={timeout}s)...")

        while time.time() - start_time < timeout:
            try:
                res = subprocess.run(
                    [self.adb_path, "devices"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                output = res.stdout if res.returncode == 0 else ""

                if "device" in output and "offline" not in output:
                    # Check if boot is completed if device is listed
                    boot_res = subprocess.run(
                        [self.adb_path, "shell", "getprop", "sys.boot_completed"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if boot_res.stdout.strip() == "1" or "device" in output:
                        logger.info("Emulator ADB status: READY")
                        print("[SANDBOX LOG] Emulator ADB status: READY")
                        return True
            except Exception as exc:
                logger.warning(f"ADB polling encountered transient error: {exc}")

            time.sleep(2)

        err_msg = f"Emulator failed to reach ready state within {timeout} seconds."
        logger.error(err_msg)
        print(f"[SANDBOX ERROR] {err_msg}")
        raise TimeoutError(err_msg)

    def restore_snapshot(self) -> None:
        """
        Restores the AVD emulator to a clean snapshot state using ADB.
        """
        logger.info(f"Restoring AVD clean snapshot: '{self.snapshot_name}'...")
        print(f"[SANDBOX LOG] Restoring AVD snapshot '{self.snapshot_name}'...")

        try:
            res = subprocess.run(
                [self.adb_path, "emu", "avd", "snapshot", "load", self.snapshot_name],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                logger.warning(f"Snapshot load output: {res.stderr or res.stdout}")
        except Exception as exc:
            err_msg = f"Failed to restore snapshot '{self.snapshot_name}': {str(exc)}"
            logger.error(err_msg)
            print(f"[SANDBOX ERROR] {err_msg}")
            raise RuntimeError(err_msg) from exc

    def stop_emulator(self) -> None:
        """
        Terminates the emulator process and sends shutdown commands cleanly.
        """
        logger.info("Stopping Android emulator...")
        print("[SANDBOX LOG] Stopping emulator process...")

        try:
            subprocess.run(
                [self.adb_path, "emu", "kill"],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as exc:
            logger.warning(f"ADB emu kill failed: {exc}")

        if self.process is not None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            finally:
                self.process = None

        logger.info("Emulator process stopped.")
        print("[SANDBOX LOG] Emulator process terminated cleanly.")
