"""
ADB Helper & Device Manager for Android Malware Analysis Sandbox
Provides robust, repeatable ADB connection checking, boot status polling,
root verification, and system property extraction.
"""

import subprocess
import time
import sys
from typing import Dict, Any, Optional, List
from colorama import init, Fore, Style

init(autoreset=True)


class ADBManager:
    def __init__(self, adb_path: str = "adb", device_id: Optional[str] = None):
        self.adb_path = adb_path
        self.device_id = device_id

    def _run_cmd(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        cmd = [self.adb_path]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(args)
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)

    def check_adb_available(self) -> bool:
        """Verifies if ADB is present and executable."""
        try:
            res = subprocess.run([self.adb_path, "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.returncode == 0
        except FileNotFoundError:
            return False

    def list_devices(self) -> List[Dict[str, str]]:
        """Returns a list of connected devices and their states."""
        res = subprocess.run([self.adb_path, "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        devices = []
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    devices.append({"id": parts[0], "state": parts[1]})
        return devices

    def wait_for_device(self, timeout: int = 180) -> bool:
        """Waits for the emulator/device to become detected and online."""
        print(f"{Fore.CYAN}[*] Waiting for ADB device to become available (timeout: {timeout}s)...{Style.RESET_ALL}")
        start_time = time.time()
        while time.time() - start_time < timeout:
            devices = self.list_devices()
            for dev in devices:
                if (not self.device_id and dev["state"] == "device") or (self.device_id and dev["id"] == self.device_id and dev["state"] == "device"):
                    if not self.device_id:
                        self.device_id = dev["id"]
                    print(f"{Fore.GREEN}[+] Detected online device: {self.device_id}{Style.RESET_ALL}")
                    return True
            time.sleep(3)
        print(f"{Fore.RED}[!] Timeout reached waiting for online device.{Style.RESET_ALL}")
        return False

    def wait_for_boot_complete(self, timeout: int = 180) -> bool:
        """Polls Android system properties until boot completion is reported."""
        print(f"{Fore.CYAN}[*] Polling Android boot completion (sys.boot_completed)...{Style.RESET_ALL}")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                res = self._run_cmd(["shell", "getprop", "sys.boot_completed"])
                if res.returncode == 0 and res.stdout.strip() == "1":
                    # Double check package manager readiness
                    pm_res = self._run_cmd(["shell", "pm", "path", "android"])
                    if pm_res.returncode == 0:
                        print(f"{Fore.GREEN}[+] Android system boot completed successfully!{Style.RESET_ALL}")
                        return True
            except Exception:
                pass
            time.sleep(3)
        print(f"{Fore.RED}[!] Timeout waiting for sys.boot_completed == 1.{Style.RESET_ALL}")
        return False

    def verify_and_enable_root(self) -> Dict[str, Any]:
        """
        Attempts to restart adbd with root permissions and verifies uid=0.
        Does NOT assume adb root succeeded without checking actual output.
        """
        print(f"{Fore.CYAN}[*] Requesting and verifying root privileges...{Style.RESET_ALL}")
        root_cmd = self._run_cmd(["root"])
        out_msg = (root_cmd.stdout + root_cmd.stderr).strip()
        print(f"{Fore.BLUE}[i] adb root response: {out_msg}{Style.RESET_ALL}")

        # Short pause for adbd restart if applicable
        time.sleep(2)

        # Explicit verification through id command
        id_res = self._run_cmd(["shell", "id"])
        id_output = id_res.stdout.strip()
        is_root = "uid=0(root)" in id_output

        result = {
            "root_command_output": out_msg,
            "id_output": id_output,
            "is_root": is_root
        }

        if is_root:
            print(f"{Fore.GREEN}[+] Root access confirmed: {id_output}{Style.RESET_ALL}")
            # Ensure SELinux is set to Permissive for Frida dynamic instrumentation
            self._run_cmd(["shell", "setenforce", "0"])
        else:
            print(f"{Fore.YELLOW}[!] Root access not available: {id_output}{Style.RESET_ALL}")

        return result

    def get_system_info(self) -> Dict[str, str]:
        """Extracts emulator environment attributes for diagnostic logging."""
        props = {
            "release": "ro.build.version.release",
            "sdk": "ro.build.version.sdk",
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "abi": "ro.product.cpu.abi",
            "fingerprint": "ro.build.fingerprint"
        }
        info = {}
        for key, prop in props.items():
            res = self._run_cmd(["shell", "getprop", prop])
            info[key] = res.stdout.strip() if res.returncode == 0 else "UNKNOWN"
        return info


def run_diagnostics():
    """Runs a complete standalone ADB diagnostic verification."""
    print(f"\n{Fore.MAGENTA}=== ANDROID ADB & EMULATOR DIAGNOSTICS ==={Style.RESET_ALL}")
    manager = ADBManager()
    
    if not manager.check_adb_available():
        print(f"{Fore.RED}[ERROR] ADB binary is not recognized or not in PATH.{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}[+] ADB binary verified.{Style.RESET_ALL}")
    
    if not manager.wait_for_device(timeout=90):
        print(f"{Fore.RED}[ERROR] No online Android device found.{Style.RESET_ALL}")
        sys.exit(1)
        
    if not manager.wait_for_boot_complete(timeout=120):
        print(f"{Fore.RED}[ERROR] Android boot did not complete within the timeout.{Style.RESET_ALL}")
        sys.exit(1)
        
    root_status = manager.verify_and_enable_root()
    sys_info = manager.get_system_info()
    
    print(f"\n{Fore.CYAN}--- EMULATOR SYSTEM INFORMATION ---{Style.RESET_ALL}")
    for k, v in sys_info.items():
        print(f"  {Fore.YELLOW}{k.capitalize():14}: {Fore.WHITE}{v}")
    print(f"  {Fore.YELLOW}{'Root Access':14}: {Fore.GREEN if root_status['is_root'] else Fore.RED}{root_status['is_root']} ({root_status['id_output']}){Style.RESET_ALL}\n")


if __name__ == "__main__":
    run_diagnostics()
