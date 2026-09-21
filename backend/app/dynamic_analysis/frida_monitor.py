"""Module for attaching Frida dynamic instrumentation hooks and collecting behavior events."""

import logging
import os
from typing import Any, Dict, List, Optional

try:
    import frida
except ImportError:
    frida = None

logger = logging.getLogger("frida_monitor")


class FridaMonitor:
    """Attaches Frida JS hooks to a running Android process and categorizes behavior events."""

    def __init__(self):
        self.session: Optional[Any] = None
        self.script: Optional[Any] = None
        self.events: List[Dict[str, Any]] = []

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
        Categorizes collected Frida events into 'file_activity' and 'api_calls'.

        :return: Dict containing 'file_activity' list and 'api_calls' list.
        """
        file_activity: List[Dict[str, Any]] = []
        api_calls: List[Dict[str, Any]] = []

        for evt in self.events:
            category = evt.get("category")
            if category == "file_activity":
                file_activity.append(evt)
            else:
                api_calls.append(evt)

        return {
            "file_activity": file_activity,
            "api_calls": api_calls,
        }
