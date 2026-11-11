"""Module for attaching Frida dynamic instrumentation hooks and collecting behavior events."""

import logging
import os
import subprocess
import time
from typing import Any, Dict, List, Optional

try:
    import frida
except ImportError:
    frida = None

logger = logging.getLogger("frida_monitor")


class FridaMonitor:
    """Attaches Frida JS hooks to a running Android process, manages daemon readiness,
    and categorizes real-time behavioral events.
    """

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path
        self.session: Optional[Any] = None
        self.script: Optional[Any] = None
        self.events: List[Dict[str, Any]] = []

    def ensure_server_running(self) -> bool:
        """Verifies if frida-server is running on the Android emulator; deploys/launches it if needed."""
        if frida is None:
            return False

        try:
            device = frida.get_usb_device(timeout=2)
            if len(device.enumerate_processes()) > 0:
                logger.info("Frida server is already active and responsive on device.")
                return True
        except Exception:
            pass

        # Try to launch frida-server via ADB
        logger.info("Frida server not responding. Attempting automated deployment/launch via ADB...")
        try:
            subprocess.run([self.adb_path, "root"], capture_output=True, text=True, check=False)
            time.sleep(1)
            subprocess.run([self.adb_path, "shell", "setenforce", "0"], capture_output=True, text=True, check=False)

            # Check if binary exists on device
            check_res = subprocess.run(
                [self.adb_path, "shell", "[ -f /data/local/tmp/frida-server ] && echo exists"],
                capture_output=True,
                text=True,
                check=False,
            )

            if "exists" not in check_res.stdout:
                # Look for local binary
                base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
                local_candidates = [
                    os.path.join(base_dir, "tools", "frida-server"),
                    os.path.join(base_dir, "sandbox", "tools", "frida-server"),
                ]
                local_bin = next((p for p in local_candidates if os.path.exists(p)), None)
                if local_bin:
                    subprocess.run([self.adb_path, "push", local_bin, "/data/local/tmp/frida-server"], check=False)
                    subprocess.run([self.adb_path, "shell", "chmod 755 /data/local/tmp/frida-server"], check=False)

            # Start daemon in background
            subprocess.run([self.adb_path, "shell", "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"], check=False)
            time.sleep(2)

            device = frida.get_usb_device(timeout=4)
            return len(device.enumerate_processes()) > 0
        except Exception as exc:
            logger.warning(f"Could not automatically initialize frida-server on device: {exc}")
            return False

    def _on_message(self, message: Dict[str, Any], data: Any) -> None:
        """Callback handler invoked when Frida script calls send()."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                logger.debug(f"Frida behavior event received: {payload}")
                self.events.append(payload)

    def attach(self, package_name: str, script_path: str = "sandbox/frida_scripts/behavior_hooks.js") -> bool:
        """
        Attaches Frida to the running Android app process and loads the instrumentation script.

        :param package_name: Target app package name.
        :param script_path: Path to the Frida JS script.
        :return: True if successfully attached and script loaded, False otherwise.
        """
        self.events.clear()

        if frida is None:
            logger.warning("Frida module is not installed in Python environment.")
            print("[FRIDA WARNING] Frida library unavailable.")
            return False

        if not os.path.isabs(script_path):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            script_path = os.path.join(base_dir, script_path)

        if not os.path.exists(script_path):
            logger.error(f"Frida script file not found at path: {script_path}")
            return False

        # Ensure server is alive
        self.ensure_server_running()

        try:
            with open(script_path, "r", encoding="utf-8") as sf:
                js_code = sf.read()

            logger.info(f"Attaching Frida to target package '{package_name}'...")
            print(f"[FRIDA LOG] Attaching to package '{package_name}'...")

            # Get USB device (emulator or connected device)
            device = frida.get_usb_device(timeout=5)
            self.session = device.attach(package_name)
            self.script = self.session.create_script(js_code)
            self.script.on("message", self._on_message)
            self.script.load()

            logger.info(f"Frida instrumentation script loaded for '{package_name}'.")
            print(f"[FRIDA LOG] Frida hooks loaded successfully for '{package_name}'.")
            return True
        except Exception as exc:
            logger.warning(f"Failed to attach Frida to package '{package_name}': {exc}")
            print(f"[FRIDA WARNING] Could not attach Frida to '{package_name}': {exc}")
            return False

    def detach(self) -> None:
        """Unloads the Frida script and detaches from the process."""
        if self.script is not None:
            try:
                self.script.unload()
            except Exception as exc:
                logger.warning(f"Error unloading Frida script: {exc}")
            finally:
                self.script = None

        if self.session is not None:
            try:
                self.session.detach()
            except Exception as exc:
                logger.warning(f"Error detaching Frida session: {exc}")
            finally:
                self.session = None

        logger.info("Frida session detached.")
        print("[FRIDA LOG] Frida session detached cleanly.")

    def get_events(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorizes collected Frida events into:
        - file_activity
        - api_calls
        - sms_interceptions
        - process_executions
        - dynamic_dex_loads

        :return: Dict containing categorized event lists.
        """
        file_activity: List[Dict[str, Any]] = []
        api_calls: List[Dict[str, Any]] = []
        sms_interceptions: List[Dict[str, Any]] = []
        process_executions: List[Dict[str, Any]] = []
        dynamic_dex_loads: List[Dict[str, Any]] = []

        for evt in self.events:
            category = str(evt.get("category", "")).lower()
            if category in ("file_activity", "file_activities"):
                file_activity.append(evt)
            elif category in ("sms_interception", "sms_interceptions"):
                sms_interceptions.append(evt)
            elif category in ("process_execution", "process_executions"):
                process_executions.append(evt)
            elif category in ("dynamic_dex_load", "dynamic_dex_loads"):
                dynamic_dex_loads.append(evt)
            else:
                api_calls.append(evt)

        return {
            "file_activity": file_activity,
            "api_calls": api_calls,
            "sms_interceptions": sms_interceptions,
            "process_executions": process_executions,
            "dynamic_dex_loads": dynamic_dex_loads,
            "total_events": len(self.events),
        }
