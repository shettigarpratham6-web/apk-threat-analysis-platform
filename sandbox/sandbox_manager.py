"""
Central Sandbox Orchestrator for Android Malware Analysis & C2 Detection
Coordinates emulator lifecycle, network proxy interception, certificate deployment,
Frida dynamic instrumentation, static manifest analysis, and automated reporting.
"""

import os
import sys
import time
import json
import uuid
import datetime
import subprocess
import frida
from typing import Dict, Any, List, Optional
from colorama import init, Fore, Style

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Internal Sandbox Modules
from sandbox.adb_helper import ADBManager
from sandbox.cert_installer import CertificateInstaller
from sandbox.frida_helper import FridaManager
from sandbox.apk_analyzer import APKAnalyzer
from sandbox.network_analyzer import NetworkAnalyzer
from sandbox.c2_detector import C2Detector
from sandbox.report_generator import ReportGenerator

init(autoreset=True)


class SandboxManager:
    def __init__(self, config_file: str = "config/config.json"):
        self.config_file = config_file
        self.config = self._load_config()

        self.sdk_path = self.config.get("environment", {}).get("android_sdk_path", r"C:\Users\UJWAL\AppData\Local\Android\Sdk")
        self.avd_name = self.config.get("emulator", {}).get("avd_name", "malware_sandbox")
        self.proxy_port = self.config.get("proxy", {}).get("port", 8080)
        self.adb_bin = "adb"
        self.emulator_bin = os.path.join(self.sdk_path, "emulator", "emulator.exe")

        # Subsystems
        self.adb_manager = ADBManager(adb_path=self.adb_bin)
        self.cert_installer = CertificateInstaller(adb_path=self.adb_bin)
        self.frida_manager = FridaManager(adb_path=self.adb_bin)
        self.c2_detector = C2Detector(self.config)
        self.report_gen = ReportGenerator(output_dir="reports")

        # Active processes
        self.mitm_proc: Optional[subprocess.Popen] = None
        self.logcat_proc: Optional[subprocess.Popen] = None
        self.emulator_proc: Optional[subprocess.Popen] = None
        self.active_session_id: Optional[str] = None
        self.collected_frida_events: List[Dict[str, Any]] = []

    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def is_emulator_running(self) -> bool:
        devices = self.adb_manager.list_devices()
        return any(d["state"] == "device" for d in devices)

    def start_emulator(self) -> bool:
        """Starts the configured AVD if not already running."""
        if self.is_emulator_running():
            print(f"{Fore.GREEN}[+] Emulator device is already online and connected.{Style.RESET_ALL}")
            return True

        print(f"{Fore.CYAN}[*] Launching Android emulator ({self.avd_name})...{Style.RESET_ALL}")
        cmd = [
            self.emulator_bin,
            "-avd", self.avd_name,
            "-writable-system",
            "-no-snapshot",
            "-no-audio"
        ]
        self.emulator_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self.wait_for_boot()

    def wait_for_boot(self, timeout: int = 120) -> bool:
        if not self.adb_manager.wait_for_device(timeout=timeout):
            return False
        return self.adb_manager.wait_for_boot_complete(timeout=timeout)

    def check_adb(self) -> bool:
        return self.adb_manager.check_adb_available() and self.adb_manager.verify_and_enable_root()["is_root"]

    def configure_proxy(self, enable: bool = True) -> bool:
        """Configures or clears Android global HTTP proxy for mitmproxy."""
        if enable:
            val = f"10.0.2.2:{self.proxy_port}"
            print(f"{Fore.CYAN}[*] Setting Android global proxy to {val}...{Style.RESET_ALL}")
            subprocess.run([self.adb_bin, "shell", f"settings put global http_proxy {val}"], check=True)
        else:
            print(f"{Fore.CYAN}[*] Resetting Android global proxy...{Style.RESET_ALL}")
            subprocess.run([self.adb_bin, "shell", "settings put global http_proxy :0"], check=True)
        return True

    def install_certificate(self) -> bool:
        return self.cert_installer.install()

    def start_frida(self) -> bool:
        return self.frida_manager.deploy_and_start()

    def start_mitmproxy(self, flow_output_path: str) -> bool:
        """Starts mitmdump in non-blocking daemon mode."""
        self.stop_mitmproxy()
        print(f"{Fore.CYAN}[*] Starting mitmproxy on port {self.proxy_port} (saving to: {flow_output_path})...{Style.RESET_ALL}")
        os.makedirs(os.path.dirname(os.path.abspath(flow_output_path)), exist_ok=True)
        mitmdump_exe = os.path.join(os.path.dirname(sys.executable), "mitmdump.exe")
        if not os.path.exists(mitmdump_exe):
            mitmdump_exe = "mitmdump"

        mitm_cmd = [
            mitmdump_exe,
            "--listen-host", "0.0.0.0",
            "-p", str(self.proxy_port),
            "--set", "block_global=false",
            "-w", flow_output_path
        ]
        self.mitm_proc = subprocess.Popen(mitm_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        return self.mitm_proc.poll() is None

    def stop_mitmproxy(self):
        if self.mitm_proc and self.mitm_proc.poll() is None:
            self.mitm_proc.terminate()
            try:
                self.mitm_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.mitm_proc.kill()
            self.mitm_proc = None

    def start_logcat(self, logcat_path: str):
        """Starts background logcat recording."""
        os.makedirs(os.path.dirname(os.path.abspath(logcat_path)), exist_ok=True)
        subprocess.run([self.adb_bin, "logcat", "-c"])  # Clear buffer
        log_file = open(logcat_path, "w", encoding="utf-8")
        self.logcat_proc = subprocess.Popen([self.adb_bin, "logcat", "-v", "time"], stdout=log_file, stderr=subprocess.DEVNULL)

    def stop_logcat(self):
        if self.logcat_proc and self.logcat_proc.poll() is None:
            self.logcat_proc.terminate()
            self.logcat_proc = None

    def install_apk(self, apk_path: str) -> bool:
        print(f"{Fore.CYAN}[*] Installing target APK: {apk_path}...{Style.RESET_ALL}")
        res = subprocess.run([self.adb_bin, "install", "-r", "-g", apk_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "Success" in res.stdout:
            print(f"{Fore.GREEN}[+] APK installed successfully.{Style.RESET_ALL}")
            return True
        print(f"{Fore.RED}[!] APK installation failed: {res.stdout} {res.stderr}{Style.RESET_ALL}")
        return False

    def uninstall_apk(self, package_name: str):
        subprocess.run([self.adb_bin, "uninstall", package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def analyse_apk(self, apk_path: str, duration_seconds: int = 15) -> Dict[str, Any]:
        """
        Executes complete multi-stage analysis pipeline:
        Static -> Environment Prep -> Installation -> Frida Injection -> Launch -> Dynamic Capture -> Report.
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"Target APK does not exist: {apk_path}")

        session_id = f"session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.path.basename(apk_path).replace('.apk', '')}"
        print(f"\n{Fore.MAGENTA}===================================================={Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}   STARTING ANALYSIS SESSION: {session_id}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}===================================================={Style.RESET_ALL}\n")

        # Stage 1: Static Analysis
        print(f"{Fore.CYAN}[STAGE 1] Running Static Bytecode & Manifest Analysis...{Style.RESET_ALL}")
        apk_analyzer = APKAnalyzer(apk_path)
        static_data = apk_analyzer.generate_report()
        package_name = static_data["metadata"]["package_name"]
        print(f"{Fore.GREEN}[+] Identified Package: {package_name} (Risk Score: {static_data['risk_assessment']['heuristic_score']}/100){Style.RESET_ALL}")

        # Stage 2: Sandbox Readiness Check
        print(f"\n{Fore.CYAN}[STAGE 2] Verifying Sandbox Environment Readiness...{Style.RESET_ALL}")
        if not self.start_emulator():
            raise RuntimeError("Failed to verify online Android emulator.")
        if not self.check_adb():
            raise RuntimeError("ADB root access is unavailable on the target emulator.")
        
        self.install_certificate()
        self.configure_proxy(enable=True)
        if not self.start_frida():
            raise RuntimeError("Failed to connect to Frida server on Android emulator.")

        # Stage 3: Setup Session Captures
        flow_path = os.path.join("logs", "traffic", f"{session_id}.flow")
        logcat_path = os.path.join("logs", "logcat", f"{session_id}.log")
        frida_log_path = os.path.join("logs", "frida", f"{session_id}.log")

        self.start_mitmproxy(flow_path)
        self.start_logcat(logcat_path)

        # Stage 4: Install Target Application
        print(f"\n{Fore.CYAN}[STAGE 3] Deploying Target Application...{Style.RESET_ALL}")
        if not self.install_apk(apk_path):
            raise RuntimeError("Target APK installation failed.")

        # Stage 5: Frida Instrumentation Injection
        print(f"\n{Fore.CYAN}[STAGE 4] Attaching Frida Dynamic Instrumentation...{Style.RESET_ALL}")
        self.collected_frida_events = []
        device = frida.get_usb_device(timeout=5)

        # Load JS hooks
        hook_scripts = ["hook_network.js", "hook_sms.js", "hook_system.js"]
        combined_js = ""
        for h in hook_scripts:
            h_path = os.path.join("sandbox", "frida_scripts", h)
            if os.path.exists(h_path):
                with open(h_path, "r", encoding="utf-8") as f:
                    combined_js += f.read() + "\n"

        def on_message(message, data):
            if message["type"] == "send":
                try:
                    payload = json.loads(message["payload"])
                    self.collected_frida_events.append(payload)
                except Exception:
                    pass

        # Spawn or launch package under Frida supervision
        try:
            pid = device.spawn([package_name])
            session = device.attach(pid)
            script = session.create_script(combined_js)
            script.on("message", on_message)
            script.load()
            device.resume(pid)
            print(f"{Fore.GREEN}[+] Target app spawned with PID {pid} under Frida supervision.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Frida spawn failed ({e}). Attempting am start fallback...{Style.RESET_ALL}")
            subprocess.run([self.adb_bin, "shell", f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1"], stdout=subprocess.DEVNULL)
            time.sleep(2)
            try:
                session = device.attach(package_name)
                script = session.create_script(combined_js)
                script.on("message", on_message)
                script.load()
                print(f"{Fore.GREEN}[+] Attached Frida to running process: {package_name}{Style.RESET_ALL}")
            except Exception as e2:
                print(f"{Fore.YELLOW}[!] Non-fatal Frida attach warning: {e2}{Style.RESET_ALL}")

        # Stage 6: Dynamic Observation Period
        print(f"\n{Fore.CYAN}[STAGE 5] Monitoring live dynamic behavior for {duration_seconds} seconds...{Style.RESET_ALL}")
        for sec in range(duration_seconds):
            time.sleep(1)
            print(f"\r  {Fore.BLUE}[i] Running: {sec + 1}/{duration_seconds}s (Events: {len(self.collected_frida_events)}){Style.RESET_ALL}", end="")
        print()

        # Stage 7: Teardown and Data Collection
        print(f"\n{Fore.CYAN}[STAGE 6] Stopping Application & Finalizing Telemetry...{Style.RESET_ALL}")
        subprocess.run([self.adb_bin, "shell", f"am force-stop {package_name}"])
        self.stop_mitmproxy()
        self.stop_logcat()

        # Save Frida events
        os.makedirs(os.path.dirname(os.path.abspath(frida_log_path)), exist_ok=True)
        with open(frida_log_path, "w", encoding="utf-8") as f:
            json.dump(self.collected_frida_events, f, indent=2)

        # Stage 8: Network & C2 Analysis
        print(f"\n{Fore.CYAN}[STAGE 7] Analyzing Captured Traffic & Evaluating C2 Indicators...{Style.RESET_ALL}")
        net_analyzer = NetworkAnalyzer(flow_path)
        network_data = net_analyzer.analyze()
        c2_data = self.c2_detector.analyze_network_data(network_data)

        print(f"  {Fore.YELLOW}Total Connections Captured : {Fore.WHITE}{network_data['total_connections']}")
        print(f"  {Fore.YELLOW}Unique Dest IPs / Domains  : {Fore.WHITE}{network_data['unique_destinations']}")
        print(f"  {Fore.YELLOW}C2 Detection Risk Score    : {Fore.RED if c2_data['c2_heuristic_score'] >= 60 else (Fore.YELLOW if c2_data['c2_heuristic_score'] >= 30 else Fore.GREEN)}{c2_data['c2_heuristic_score']}/100 ({c2_data['risk_level']})")

        # Stage 9: Generate Final Forensic Reports
        print(f"\n{Fore.CYAN}[STAGE 8] Generating Forensic Reports...{Style.RESET_ALL}")
        final_report = self.report_gen.generate_unified_report(
            session_id=session_id,
            static_data=static_data,
            network_data=network_data,
            c2_data=c2_data,
            frida_events=self.collected_frida_events,
            logcat_summary={"log_file": logcat_path, "status": "Captured"}
        )
        saved_paths = self.report_gen.save_reports(final_report)

        print(f"\n{Fore.GREEN}===================================================={Style.RESET_ALL}")
        print(f"{Fore.GREEN}   ANALYSIS COMPLETED FOR: {os.path.basename(apk_path)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}   Overall Verdict   : {final_report['overall_verdict']}")
        print(f"{Fore.GREEN}   Risk Score        : {final_report['overall_risk_score']}/100")
        print(f"{Fore.GREEN}   JSON Report       : {saved_paths['json']}")
        print(f"{Fore.GREEN}   HTML Report       : {saved_paths['html']}")
        print(f"{Fore.GREEN}====================================================\n{Style.RESET_ALL}")

        return final_report

    def stop_all(self):
        """Cleanup handler."""
        self.stop_mitmproxy()
        self.stop_logcat()
        self.configure_proxy(enable=False)
        print(f"{Fore.GREEN}[+] Sandbox cleanup complete.{Style.RESET_ALL}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sandbox_manager.py <path_to_apk> [duration_seconds]")
        sys.exit(1)

    target_apk = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15

    manager = SandboxManager()
    try:
        manager.analyse_apk(target_apk, duration_seconds=duration)
    finally:
        manager.stop_all()
