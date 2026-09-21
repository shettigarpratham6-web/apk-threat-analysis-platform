"""Module for managing mitmproxy network traffic interception and log parsing."""

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("network_monitor")


class NetworkMonitor:
    """Launches mitmdump traffic logger subprocess and parses generated JSON lines logs."""

    def __init__(self, addon_script_path: str = "sandbox/mitmproxy_config/traffic_logger.py"):
        if not os.path.isabs(addon_script_path):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            addon_script_path = os.path.join(base_dir, addon_script_path)

        self.addon_script_path = addon_script_path
        self.process: Optional[subprocess.Popen] = None

    def start(self, output_path: str) -> None:
        """
        Launches mitmdump in background to intercept and record network traffic.

        NOTE: For the Android emulator to route traffic through mitmproxy, configure the emulator
        proxy via '-http-proxy 127.0.0.1:8080' or run:
        'adb shell settings put global http_proxy 127.0.0.1:8080'
        """
        # Ensure target log output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        cmd = [
            "mitmdump",
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

    def stop(self) -> None:
        """Terminates the mitmdump proxy process cleanly."""
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
