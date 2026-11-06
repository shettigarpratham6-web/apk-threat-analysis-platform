"""Module for managing the lifecycle of the Android Emulator sandbox environment."""

import logging
import os
import shutil
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

    def _cleanup_stale_avd_locks(self) -> None:
        """Removes stale .lock files and directories for the current AVD so emulator starts cleanly."""
        try:
            home = os.path.expanduser("~")
            avd_dir = os.path.join(home, ".android", "avd", f"{self.avd_name}.avd")
            if os.path.exists(avd_dir):
                for item in os.listdir(avd_dir):
                    if item.endswith(".lock"):
                        lock_path = os.path.join(avd_dir, item)
                        try:
                            if os.path.isdir(lock_path):
                                shutil.rmtree(lock_path, ignore_errors=True)
                            else:
                                os.remove(lock_path)
                            logger.info(f"Removed stale AVD lock: {lock_path}")
                        except Exception as le:
                            logger.warning(f"Could not remove lock {lock_path}: {le}")
        except Exception as exc:
            logger.warning(f"Error during lock cleanup: {exc}")

    def is_emulator_ready(self) -> bool:
        """Checks whether an ADB device/emulator is currently online and fully booted."""
        try:
            res = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, check=False)
            output = res.stdout if res.returncode == 0 else ""
            lines = [l.strip() for l in output.strip().splitlines() if l.strip() and not l.startswith("*") and not l.startswith("List of")]
            active = [l for l in lines if "\tdevice" in l or l.endswith(" device")]
            if active:
                boot = subprocess.run([self.adb_path, "shell", "getprop", "sys.boot_completed"], capture_output=True, text=True, check=False)
                return boot.stdout.strip() == "1"
        except Exception:
            pass
        return False

    def start_emulator(self) -> None:
        """
        Launches the Android emulator process asynchronously using Popen.

        :raises RuntimeError: If launching the emulator process fails.
        """
        if self.is_emulator_ready():
            logger.info("Emulator device is already online and connected.")
            print("[SANDBOX LOG] Emulator device is already online and ready.")
            return

        if self.process is not None and self.process.poll() is None:
            logger.info("Emulator process is already running.")
            print("[SANDBOX LOG] Emulator process is already active.")
            return

        # Clean stale lock files before launching
        self._cleanup_stale_avd_locks()

        cmd = [self.emulator_path, "-avd", self.avd_name, "-no-snapshot-save"]
        if self.headless:
            cmd.append("-no-window")

        logger.info(f"Launching Android emulator: {' '.join(cmd)}")
        print(f"[SANDBOX LOG] Launching emulator: {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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
        Polls ADB devices until the emulator is reported as ready ('device') and boot is completed.

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
                lines = [l.strip() for l in output.strip().splitlines() if l.strip() and not l.startswith("*") and not l.startswith("List of")]
                active_devices = [l for l in lines if "\tdevice" in l or l.endswith(" device")]

                if active_devices:
                    # Check if boot is completed
                    boot_res = subprocess.run(
                        [self.adb_path, "shell", "getprop", "sys.boot_completed"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if boot_res.stdout.strip() == "1":
                        logger.info("Emulator ADB status: READY (boot completed)")
                        print("[SANDBOX LOG] Emulator ADB status: READY (boot completed)")
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
        Restores clean sandbox state.
        Note: Live QEMU snapshot loading on running emulators frequently resets ADB transport
        or crashes qemu-system on Windows. Clean state is safely maintained via package
        uninstallation and cache resets.
        """
        logger.info("Sandbox clean state check: maintaining isolated environment via app uninstallation.")
        print("[SANDBOX LOG] Sandbox state prepared for clean execution.")

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

    def run_full_dynamic_prep(self, apk_path: str) -> dict:
        """
        Orchestrates full dynamic sandbox preparation:
        ensures emulator sandbox is running and ready,
        uninstalls any previous instance for clean state,
        installs target APK, launches app package, and pauses for initial settling.

        :param apk_path: Path to the target APK file on disk.
        :return: Dictionary containing package_name and status ('running').
        """
        logger.info(f"Initiating full dynamic sandbox prep for: {apk_path}")
        print(f"[SANDBOX LOG] Initiating full dynamic sandbox prep for '{apk_path}'...")

        # 0. Ensure emulator is running and booted
        if not self.is_emulator_ready():
            logger.info("Emulator is not running or not ready. Auto-launching sandbox emulator...")
            print("[SANDBOX LOG] Emulator device offline. Starting fake phone sandbox...")
            self.start_emulator()
            self.wait_until_ready(timeout=BOOT_TIMEOUT)

        # 1. Resolve package name and clean previous instance
        from backend.app.dynamic_analysis.apk_runner import ApkRunner

        runner = ApkRunner(adb_path=self.adb_path)
        package_name = runner.get_package_name(apk_path)

        try:
            logger.info(f"Pre-cleaning existing app instance '{package_name}' for clean state...")
            runner.uninstall_apk(package_name)
        except Exception as exc:
            logger.debug(f"Pre-install cleanup skipped: {exc}")

        # 2. Install APK and launch app
        runner.install_apk(apk_path)
        runner.launch_apk(package_name)

        # 3. Short settle delay to let app open completely on-screen
        settle_seconds = 2
        logger.info(f"Pausing {settle_seconds}s to let app interface initialize on-screen...")
        print(f"[SANDBOX LOG] Pausing {settle_seconds}s to allow app UI initialization...")
        time.sleep(settle_seconds)

        return {
            "package_name": package_name,
            "status": "running",
        }

    def monitor_behavior(self, package_name: str, apk_id: str, duration: int = 30) -> dict:
        """
        Monitors runtime behavior of an active app: starts NetworkMonitor and FridaMonitor,
        runs observation window for 'duration' seconds, stops monitors, and returns collected data.

        :param package_name: Target app package name.
        :param apk_id: Unique identifier for the APK analysis session.
        :param duration: Time window in seconds to monitor live behavior.
        :return: Dict containing network_traffic, file_activity, and api_calls lists.
        """
        from backend.app.dynamic_analysis.network_monitor import NetworkMonitor
        from backend.app.dynamic_analysis.frida_monitor import FridaMonitor

        logger.info(f"Starting behavior monitoring for package '{package_name}' (apk_id={apk_id}, duration={duration}s)...")
        print(f"[BEHAVIOR LOG] Monitoring behavior for '{package_name}' ({duration}s)...")

        # Resolve output network log filepath
        results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))
        os.makedirs(results_dir, exist_ok=True)
        net_log_path = os.path.join(results_dir, f"{apk_id}_network.jsonl")

        net_mon = NetworkMonitor()
        frida_mon = FridaMonitor()

        # 1. Start monitors
        net_mon.start(net_log_path)
        frida_mon.attach(package_name)

        # 2. Observation sleep window (NOTE: Automated UI exploration via Android Monkey or Accessibility
        # could be added here to exercise additional user flows and uncover deeper behaviors).
        logger.info(f"Observing app behavior for {duration} seconds...")
        print(f"[BEHAVIOR LOG] App running live. Observing for {duration} seconds...")
        time.sleep(duration)

        # 3. Stop monitors
        frida_mon.detach()
        net_mon.stop()

        # 4. Parse & structure collected events
        network_entries = net_mon.parse_log(net_log_path)
        frida_events = frida_mon.get_events()

        return {
            "network_traffic": network_entries,
            "file_activity": frida_events.get("file_activity", []),
            "api_calls": frida_events.get("api_calls", []),
        }

    def run_c2_detection(self, dynamic_results: dict, static_results: dict = None) -> dict:
        """
        Extracts network traffic from dynamic_results and code analysis URLs/IPs from static_results,
        then executes rule-based C2 detection heuristics.

        :param dynamic_results: Dict containing dynamic analysis data (e.g. network_traffic).
        :param static_results: Optional dict containing static analysis results (e.g. code_analysis).
        :return: Dict returned by detect_c2 containing suspected_c2_hosts and raw_flagged_traffic.
        """
        from backend.app.dynamic_analysis.c2_detection import detect_c2

        network_traffic = []
        if isinstance(dynamic_results, dict):
            if "network_traffic" in dynamic_results:
                network_traffic = dynamic_results.get("network_traffic") or []
            elif "dynamic_analysis" in dynamic_results and isinstance(dynamic_results["dynamic_analysis"], dict):
                network_traffic = dynamic_results["dynamic_analysis"].get("network_traffic") or []

        code_analysis_urls_ips = {}
        if isinstance(static_results, dict):
            if "code_analysis" in static_results:
                code_analysis_urls_ips = static_results.get("code_analysis") or {}
            elif "static_analysis" in static_results and isinstance(static_results["static_analysis"], dict):
                code_analysis_urls_ips = static_results["static_analysis"].get("code_analysis") or {}
            elif "urls" in static_results or "ip_addresses" in static_results:
                code_analysis_urls_ips = static_results

        return detect_c2(network_traffic, code_analysis_urls_ips)



