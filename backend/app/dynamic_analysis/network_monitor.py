"""Module for managing mitmproxy network traffic interception and log parsing."""

import json
import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("network_monitor")


class NetworkMonitor:
    """Launches mitmdump traffic logger subprocess, manages Android emulator proxy configuration,
    and parses generated JSON lines logs.
    """

    def __init__(self, addon_script_path: str = "sandbox/mitmproxy_config/traffic_logger.py"):
        if not os.path.isabs(addon_script_path):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            addon_script_path = os.path.join(base_dir, addon_script_path)

        self.addon_script_path = addon_script_path
        self.process: Optional[subprocess.Popen] = None

    @staticmethod
    def enable_emulator_proxy(adb_path: str = "adb", proxy_address: str = "10.0.2.2:8080") -> bool:
        """Configures the global Android emulator HTTP proxy via ADB settings."""
        try:
            cmd = [adb_path, "shell", "settings", "put", "global", "http_proxy", proxy_address]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                logger.info(f"Configured Android emulator HTTP proxy: {proxy_address}")
                print(f"[NETWORK LOG] Android global HTTP proxy routed to {proxy_address}")
                return True
        except Exception as exc:
            logger.warning(f"Failed to set emulator global proxy: {exc}")
        return False

    @staticmethod
    def disable_emulator_proxy(adb_path: str = "adb") -> bool:
        """Clears the global Android emulator HTTP proxy via ADB settings."""
        try:
            cmd = [adb_path, "shell", "settings", "put", "global", "http_proxy", ":0"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                logger.info("Cleared Android emulator global HTTP proxy.")
                print("[NETWORK LOG] Android global HTTP proxy cleared.")
                return True
        except Exception as exc:
            logger.warning(f"Failed to clear emulator global proxy: {exc}")
        return False

    def start(self, output_path: str, adb_path: Optional[str] = None) -> None:
        """
        Launches mitmdump in background to intercept and record network traffic.
        Optionally sets the emulator's global proxy if adb_path is provided.
        """
        # Ensure target log output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        mitmdump_exe = shutil.which("mitmdump")
        if not mitmdump_exe:
            cand = os.path.join(os.path.dirname(sys.executable), "mitmdump.exe")
            if os.path.exists(cand):
                mitmdump_exe = cand
            else:
                mitmdump_exe = "mitmdump"

        cmd = [
            mitmdump_exe,
            "-s",
            self.addon_script_path,
            "--set",
            f"logfile={output_path}",
            "-p",
            "8080",
        ]

        logger.info(f"Starting mitmdump network monitor: {' '.join(cmd)}")
        print(f"[NETWORK LOG] Starting mitmdump monitor: {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
        except Exception as exc:
            logger.warning(
                f"Could not start mitmdump process (ensure mitmproxy is installed): {exc}"
            )
            print(f"[NETWORK WARNING] mitmdump process launch skipped/failed: {exc}")

        # Automatically route emulator proxy if adb_path is supplied
        if adb_path:
            self.enable_emulator_proxy(adb_path=adb_path)

    def stop(self, adb_path: Optional[str] = None) -> None:
        """Terminates the mitmdump proxy process cleanly and restores device proxy settings."""
        if adb_path:
            self.disable_emulator_proxy(adb_path=adb_path)

        if self.process is not None:
            logger.info("Stopping mitmdump network monitor...")
            print("[NETWORK LOG] Stopping mitmdump network monitor...")
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

    def parse_log(self, output_path: str) -> List[Dict[str, Any]]:
        """
        Reads the generated JSON lines log file and returns structured traffic entries.

        :param output_path: Path to the JSON lines log file.
        :return: List of parsed traffic dictionaries.
        """
        entries = []
        if not os.path.exists(output_path):
            logger.info(f"Network traffic log file '{output_path}' does not exist.")
            return entries

        try:
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            pass
        except Exception as exc:
            logger.error(f"Error parsing network traffic log file '{output_path}': {exc}")

        return entries


# Module-level convenience functions
enable_emulator_proxy = NetworkMonitor.enable_emulator_proxy
disable_emulator_proxy = NetworkMonitor.disable_emulator_proxy

