"""
Frida Manager & Server Controller
Automates binary verification, device deployment, and daemon process management.
"""

import subprocess
import time
import sys
import os
import frida
from typing import Dict, Any, List
from colorama import init, Fore, Style

init(autoreset=True)


class FridaManager:
    def __init__(
        self,
        local_server_path: str = "tools/frida-server",
        device_server_path: str = "/data/local/tmp/frida-server",
        adb_path: str = "adb"
    ):
        self.local_server_path = local_server_path
        self.device_server_path = device_server_path
        self.adb_path = adb_path
        self.expected_version = frida.__version__

    def check_local_binary(self) -> bool:
        """Verifies if the required local frida-server binary is present."""
        if not os.path.exists(self.local_server_path):
            print(f"{Fore.RED}[ERROR] Local frida-server binary missing at: {self.local_server_path}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] Expected matching Frida version: {self.expected_version} (android-x86_64){Style.RESET_ALL}")
            return False
        return True

    def is_server_running_on_device(self) -> bool:
        """Checks if frida-server is already active on the device."""
        try:
            device = frida.get_usb_device(timeout=3)
            processes = device.enumerate_processes()
            return len(processes) > 0
        except Exception:
            return False

    def deploy_and_start(self, timeout: int = 15) -> bool:
        """Pushes frida-server to device if needed and launches the background daemon."""
        print(f"\n{Fore.CYAN}[*] Initializing Frida server (v{self.expected_version})...{Style.RESET_ALL}")
        
        # Check if already running
        if self.is_server_running_on_device():
            print(f"{Fore.GREEN}[+] Frida server is already active and responsive on USB device.{Style.RESET_ALL}")
            return True

        if not self.check_local_binary():
            return False

        # Ensure root
        subprocess.run([self.adb_path, "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check device file
        check_res = subprocess.run([self.adb_path, "shell", f"[ -f {self.device_server_path} ] && echo exists"], stdout=subprocess.PIPE, text=True)
        if "exists" not in check_res.stdout:
            print(f"{Fore.CYAN}[*] Deploying frida-server to {self.device_server_path}...{Style.RESET_ALL}")
            subprocess.run([self.adb_path, "push", self.local_server_path, self.device_server_path], check=True)
            subprocess.run([self.adb_path, "shell", f"chmod 755 {self.device_server_path}"], check=True)

        # Launch server
        print(f"{Fore.CYAN}[*] Starting frida-server background daemon...{Style.RESET_ALL}")
        subprocess.run([self.adb_path, "shell", f"nohup {self.device_server_path} >/dev/null 2>&1 &"])

        # Wait for connectivity
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.is_server_running_on_device():
                print(f"{Fore.GREEN}[+] Frida server v{self.expected_version} successfully connected!{Style.RESET_ALL}")
                return True
            time.sleep(1)

        print(f"{Fore.RED}[!] Timeout reached waiting for Frida server response.{Style.RESET_ALL}")
        return False

    def list_applications(self) -> List[Dict[str, Any]]:
        """Returns the list of running Android applications."""
        device = frida.get_usb_device()
        apps = device.enumerate_applications()
        return [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps]


if __name__ == "__main__":
    manager = FridaManager()
    success = manager.deploy_and_start()
    if success:
        apps = manager.list_applications()
        print(f"{Fore.GREEN}[+] Enumerated {len(apps)} installed applications on device.{Style.RESET_ALL}")
    sys.exit(0 if success else 1)
