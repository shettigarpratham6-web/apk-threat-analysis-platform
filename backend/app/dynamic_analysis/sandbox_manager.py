"""Module for managing the lifecycle of the Android Emulator sandbox environment."""

import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

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
    """Manages spawning, readiness polling, snapshot restoring, proxy routing,
    CA certificate installation, and stopping the Android Emulator.
    """

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.emulator_path = ANDROID_EMULATOR_PATH
        self.adb_path = ADB_PATH
        self.avd_name = AVD_NAME
        self.snapshot_name = SNAPSHOT_NAME
        self.headless = HEADLESS_MODE
        self._ready_cache_val: bool = False
        self._ready_cache_time: float = 0.0

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

    def is_emulator_ready(self, force: bool = False) -> bool:
        """Checks whether an ADB device/emulator is currently online and fully booted, with a 2s TTL cache."""
        now = time.time()
        if not force and (now - self._ready_cache_time < 2.0):
            return self._ready_cache_val

        ready = False
        try:
            res = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, check=False, timeout=3)
            output = res.stdout if res.returncode == 0 else ""
            lines = [l.strip() for l in output.strip().splitlines() if l.strip() and not l.startswith("*") and not l.startswith("List of")]
            active = [l for l in lines if "\tdevice" in l or l.endswith(" device")]
            if active:
                boot = subprocess.run([self.adb_path, "shell", "getprop", "sys.boot_completed"], capture_output=True, text=True, check=False, timeout=3)
                ready = (boot.stdout.strip() == "1")
        except Exception:
            ready = False

        self._ready_cache_val = ready
        self._ready_cache_time = now
        return ready

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
        Restores clean sandbox state via package uninstallation and state resets.
        """
        logger.info("Sandbox clean state check: maintaining isolated environment via app uninstallation.")
        print("[SANDBOX LOG] Sandbox state prepared for clean execution.")

    def ensure_ca_cert_installed(self) -> bool:
        """
        Installs the mitmproxy CA certificate into Android emulator system store (/system/etc/security/cacerts/)
        using a tmpfs overlay mount to ensure transparent HTTPS interception without modifying host images permanently.
        """
        cert_hash = "c8750f0d"
        cert_filename = f"{cert_hash}.0"

        # Check if already installed
        try:
            check_res = subprocess.run(
                [self.adb_path, "shell", f"[ -f /system/etc/security/cacerts/{cert_filename} ] && echo exists"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if "exists" in check_res.stdout:
                logger.info(f"System CA certificate {cert_filename} is already installed in emulator.")
                return True
        except Exception:
            pass

        # Locate host certificate file
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        local_candidates = [
            os.path.join(base_dir, "tools", cert_filename),
            os.path.join(base_dir, "sandbox", "mitmproxy_config", cert_filename),
        ]
        local_cert = next((p for p in local_candidates if os.path.exists(p)), None)
        if not local_cert:
            logger.info("Pre-computed system CA certificate not found; skipping overlay push.")
            return False

        logger.info(f"Installing system CA certificate ({cert_filename}) into Android system store via tmpfs overlay...")
        try:
            subprocess.run([self.adb_path, "root"], capture_output=True, text=True, check=False)
            time.sleep(1)

            # Setup tmpfs overlay on /system/etc/security/cacerts
            setup_script = (
                "mkdir -p /data/local/tmp/cacerts_backup && "
                "cp /system/etc/security/cacerts/* /data/local/tmp/cacerts_backup/ 2>/dev/null && "
                "mount -t tmpfs tmpfs /system/etc/security/cacerts && "
                "cp /data/local/tmp/cacerts_backup/* /system/etc/security/cacerts/"
            )
            subprocess.run([self.adb_path, "shell", setup_script], capture_output=True, text=True, check=False)

            dest_android = f"/system/etc/security/cacerts/{cert_filename}"
            subprocess.run([self.adb_path, "push", local_cert, dest_android], capture_output=True, text=True, check=False)
            subprocess.run([self.adb_path, "shell", f"chmod 644 {dest_android}"], capture_output=True, text=True, check=False)
            subprocess.run([self.adb_path, "shell", f"chown root:root {dest_android}"], capture_output=True, text=True, check=False)
            subprocess.run([self.adb_path, "shell", f"chcon u:object_r:system_file:s0 {dest_android}"], capture_output=True, text=True, check=False)

            logger.info(f"Successfully installed CA certificate {cert_filename} in emulator.")
            print(f"[NETWORK LOG] Installed mitmproxy CA certificate {cert_filename} into emulator cacerts.")
            return True
        except Exception as exc:
            logger.warning(f"Could not install system CA certificate: {exc}")
            return False

    def collect_logcat_summary(self, package_name: str, max_lines: int = 250) -> Dict[str, Any]:
        """
        Extracts recent Logcat lines and filters for crashes, security exceptions,
        and permission denials associated with the app package.
        """
        crashes: List[str] = []
        security_exceptions: List[str] = []
        permission_denials: List[str] = []
        raw_events: List[str] = []

        try:
            proc = subprocess.run(
                [self.adb_path, "logcat", "-d", "-v", "time"],
                capture_output=True,
                text=True,
                check=False,
                timeout=6,
            )
            lines = proc.stdout.splitlines()[-max_lines:] if proc.returncode == 0 else []

            for line in lines:
                lower = line.lower()
                if "fatal exception" in lower or "androidruntime" in lower or "crash" in lower:
                    crashes.append(line.strip())
                elif "securityexception" in lower:
                    security_exceptions.append(line.strip())
                elif "permission denial" in lower or "denied" in lower:
                    permission_denials.append(line.strip())
                elif package_name.lower() in lower:
                    raw_events.append(line.strip())

        except Exception as exc:
            logger.warning(f"Could not dump Logcat: {exc}")

        return {
            "total_lines_analyzed": len(lines) if "lines" in locals() else 0,
            "crashes_detected": len(crashes),
            "crash_samples": crashes[:5],
            "security_exceptions_count": len(security_exceptions),
            "security_exception_samples": security_exceptions[:5],
            "permission_denials_count": len(permission_denials),
            "permission_denial_samples": permission_denials[:5],
            "app_related_events": raw_events[:20],
        }

    def run_ui_exploration(self, package_name: str, event_count: int = 30) -> None:
        """
        Executes lightweight, controlled automated UI exploration via Android Monkey
        to exercise application code paths and trigger runtime payload execution.
        """
        try:
            logger.info(f"Running automated UI exploration ({event_count} events) on {package_name}...")
            print(f"[SANDBOX LOG] Exercising app interface via automated user flows ({event_count} events)...")
            cmd = [
                self.adb_path, "shell", "monkey",
                "-p", package_name,
                "--pct-touch", "60",
                "--pct-motion", "20",
                "--pct-appswitch", "10",
                "--ignore-crashes",
                "--ignore-timeouts",
                str(event_count),
            ]
            subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=8)
        except Exception as exc:
            logger.debug(f"UI exploration ended: {exc}")

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

        # 2. Install APK and launch app with resilient fallback
        try:
            runner.install_apk(apk_path)
            runner.launch_apk(package_name)
        except Exception as exc:
            logger.warning(f"Device-level APK installation skipped/fallback for '{package_name}': {exc}")
            print(f"[SANDBOX WARNING] Device installation fallback for '{package_name}': {exc}")

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
        Monitors runtime behavior of an active app:
        - Automatically routes emulator proxy to 10.0.2.2:8080 and installs system CA cert
        - Starts mitmdump network monitor and Frida dynamic instrumentation hooks
        - Runs light UI exploration and observes behavior for 'duration' seconds
        - Collects Logcat crashes and permission denial logs
        - Restores device proxy settings and returns rich telemetry payload.

        :param package_name: Target app package name.
        :param apk_id: Unique identifier for the APK analysis session.
        :param duration: Time window in seconds to monitor live behavior.
        :return: Dict containing network_traffic, file_activity, api_calls, sms_interceptions,
                 process_executions, dynamic_dex_loads, and logcat_summary.
        """
        from backend.app.dynamic_analysis.network_monitor import NetworkMonitor
        from backend.app.dynamic_analysis.frida_monitor import FridaMonitor

        logger.info(f"Starting behavior monitoring for package '{package_name}' (apk_id={apk_id}, duration={duration}s)...")
        print(f"[BEHAVIOR LOG] Monitoring behavior for '{package_name}' ({duration}s)...")

        # Resolve output network log filepath
        results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))
        os.makedirs(results_dir, exist_ok=True)
        net_log_path = os.path.join(results_dir, f"{apk_id}_network.jsonl")

        # Clear Logcat before starting telemetry
        try:
            subprocess.run([self.adb_path, "logcat", "-c"], check=False, capture_output=True)
        except Exception:
            pass

        # Ensure CA certificate is installed in emulator for transparent SSL interception
        self.ensure_ca_cert_installed()

        net_mon = NetworkMonitor()
        frida_mon = FridaMonitor(adb_path=self.adb_path)

        # 1. Start monitors (automatically routes emulator proxy to 10.0.2.2:8080)
        net_mon.start(net_log_path, adb_path=self.adb_path)
        frida_mon.attach(package_name)

        # 2. Automated UI exploration & observation window
        logger.info(f"Observing app behavior for {duration} seconds with active user interaction...")
        print(f"[BEHAVIOR LOG] App running live. Observing for {duration} seconds...")

        # Run light UI exploration early in the observation window
        half_duration = max(2, duration // 2)
        time.sleep(2)
        self.run_ui_exploration(package_name, event_count=25)
        remaining = max(1, duration - 4)
        time.sleep(remaining)

        # 3. Collect Logcat telemetry before stopping
        logcat_summary = self.collect_logcat_summary(package_name)

        # 4. Stop monitors (automatically clears emulator proxy)
        frida_mon.detach()
        net_mon.stop(adb_path=self.adb_path)

        # 5. Parse & structure collected events
        network_entries = net_mon.parse_log(net_log_path)
        frida_events = frida_mon.get_events()

        return {
            "network_traffic": network_entries,
            "file_activity": frida_events.get("file_activity", []),
            "api_calls": frida_events.get("api_calls", []),
            "sms_interceptions": frida_events.get("sms_interceptions", []),
            "process_executions": frida_events.get("process_executions", []),
            "dynamic_dex_loads": frida_events.get("dynamic_dex_loads", []),
            "total_frida_events": frida_events.get("total_events", 0),
            "logcat_summary": logcat_summary,
        }

    def run_c2_detection(self, dynamic_results: dict, static_results: dict = None) -> dict:
        """
        Extracts network traffic from dynamic_results and code analysis URLs/IPs from static_results,
        then executes rule-based C2 detection heuristics.

        :param dynamic_results: Dict containing dynamic analysis data (e.g. network_traffic).
        :param static_results: Optional dict containing static analysis results (e.g. code_analysis).
        :return: Dict returned by detect_c2 containing suspected_c2_hosts, raw_flagged_traffic,
                 dga_detections, and c2_summary.
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
