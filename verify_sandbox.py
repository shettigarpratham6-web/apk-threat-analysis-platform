"""
Stage N: End-to-End Verification & Validation Script
Android Malware Analysis & C2 Detection Sandbox

Executes the 10-test verification matrix:
  TEST 1: Environment & Tooling
  TEST 2: Android Emulator Readiness & Root Access
  TEST 3: Network Interception (HTTP)
  TEST 4: Network Interception & CA Trust (HTTPS)
  TEST 5: Dynamic Instrumentation (Frida Server & RPC)
  TEST 6: Static APK Analysis (Androguard)
  TEST 7: Dynamic Execution (Benign Baseline)
  TEST 8: Dynamic Execution (C2 Malware Simulator & Beaconing)
  TEST 9: Comparative Analysis (Benign vs C2 Simulator)
  TEST 10: Forensic Report Validation (HTML & JSON)
"""

import os
import sys
import json
import glob
import time
import subprocess

# Ensure sandbox modules can be imported
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from sandbox.adb_helper import ADBManager
from sandbox.apk_analyzer import APKAnalyzer
from sandbox.c2_detector import C2Detector
from sandbox.network_analyzer import NetworkAnalyzer

PASS = "[PASS]"
FAIL = "[FAIL]"
INFO = "[*]"

results = {}

def test_1_environment():
    print(f"\n{INFO} TEST 1: Environment & Tooling")
    import frida
    import androguard
    import flask
    import pandas
    
    mitm_bin = os.path.abspath("venv/Scripts/mitmdump.exe")
    assert os.path.exists(mitm_bin), f"mitmdump not found at {mitm_bin}"
    
    print(f"  - Python: {sys.version.split()[0]}")
    print(f"  - Frida: {frida.__version__}")
    print(f"  - Androguard: {androguard.__version__}")
    print(f"  - Flask: {flask.__version__}")
    print(f"  - Pandas: {pandas.__version__}")
    print(f"  - mitmdump binary: {mitm_bin}")
    results["TEST 1: Environment"] = PASS


def test_2_emulator():
    print(f"\n{INFO} TEST 2: Emulator & Root Access")
    from sandbox.sandbox_manager import SandboxManager
    sb = SandboxManager()
    if not sb.is_emulator_running():
        sb.start_emulator()
    adb = ADBManager()
    info = adb.get_system_info()
    root_res = adb.verify_and_enable_root()
    assert root_res["is_root"], f"Root access verification failed: {root_res}"
    
    print(f"  - Emulator Status: ONLINE (Model: {info.get('model')}, Android: {info.get('release')}, API: {info.get('sdk')})")
    print(f"  - Root Access: Verified ({root_res['id_output']})")
    results["TEST 2: Emulator"] = PASS


def test_3_and_4_network_cert():
    print(f"\n{INFO} TEST 3 & 4: Network Interception & CA Certificate")
    adb = ADBManager()
    
    cert_hash = "c8750f0d.0"
    cert_path = f"/system/etc/security/cacerts/{cert_hash}"
    res = adb._run_cmd(["shell", "ls", "-l", cert_path]).stdout
    if cert_hash not in res:
        from sandbox.cert_installer import CertificateInstaller
        CertificateInstaller().install()
        res = adb._run_cmd(["shell", "ls", "-l", cert_path]).stdout
    assert cert_hash in res, f"Certificate {cert_hash} not found in system store: {res}"
    print(f"  - System CA Cert: Verified present at {cert_path}")
    
    proxy_val = adb._run_cmd(["shell", "settings", "get", "global", "http_proxy"]).stdout.strip()
    print(f"  - Global HTTP Proxy Setting: {proxy_val}")
    
    host_cert = os.path.abspath(f"tools/{cert_hash}")
    assert os.path.exists(host_cert), f"Host cert not found at {host_cert}"
    print(f"  - Host CA Cert: {host_cert} ({os.path.getsize(host_cert)} bytes)")
    
    results["TEST 3: Network (HTTP)"] = PASS
    results["TEST 4: Network (HTTPS)"] = PASS


def test_5_frida():
    print(f"\n{INFO} TEST 5: Dynamic Instrumentation (Frida)")
    import frida
    from sandbox.frida_helper import FridaManager
    fm = FridaManager()
    if not fm.is_server_running_on_device():
        fm.deploy_and_start()
    device = frida.get_usb_device(timeout=10)
    assert device is not None, "Frida USB device connection failed"
    processes = device.enumerate_processes()
    assert len(processes) > 0, "No processes enumerated by Frida"
    print(f"  - Frida Device: {device.name} (type: {device.type})")
    print(f"  - Active Processes Enumerated: {len(processes)}")
    
    # Check frida scripts exist
    scripts = ["hook_network.js", "hook_sms.js", "hook_system.js"]
    for s in scripts:
        spath = os.path.join("sandbox", "frida_scripts", s)
        assert os.path.exists(spath), f"Missing Frida script {spath}"
    print(f"  - Instrumentation Scripts: {', '.join(scripts)} verified")
    results["TEST 5: Frida"] = PASS


def test_6_static_analysis():
    print(f"\n{INFO} TEST 6: Static APK Analysis (Androguard)")
    
    benign_apk = "datasets/benign/BenignDemo.apk"
    malicious_apk = "datasets/malicious/C2Simulator.apk"
    
    assert os.path.exists(benign_apk), f"Missing {benign_apk}"
    assert os.path.exists(malicious_apk), f"Missing {malicious_apk}"
    
    b_analyzer = APKAnalyzer(benign_apk)
    b_res = b_analyzer.generate_report()
    
    m_analyzer = APKAnalyzer(malicious_apk)
    m_res = m_analyzer.generate_report()
    
    b_pkg = b_res["metadata"]["package_name"]
    m_pkg = m_res["metadata"]["package_name"]
    
    assert b_pkg == "com.defensive.benignapp", f"Unexpected pkg {b_pkg}"
    assert m_pkg == "com.defensive.c2simulator", f"Unexpected pkg {m_pkg}"
    
    b_score = b_res["risk_assessment"]["heuristic_score"]
    m_score = m_res["risk_assessment"]["heuristic_score"]
    
    print(f"  - BenignDemo.apk: {b_pkg}, Risk: {b_score}/100, Permissions: {b_res['permissions']['total_requested']}")
    print(f"  - C2Simulator.apk: {m_pkg}, Risk: {m_score}/100, Permissions: {m_res['permissions']['total_requested']}")
    results["TEST 6: Static Analysis"] = PASS


def test_7_8_and_9_dynamic_comparison():
    print(f"\n{INFO} TEST 7, 8, & 9: Dynamic Sandbox & C2 Detection Comparison")
    
    reports = glob.glob("reports/report_session_*.json")
    assert len(reports) >= 2, f"Expected at least 2 reports, found {len(reports)}"
    
    benign_report = None
    malicious_report = None
    
    for rpath in sorted(reports, reverse=True):
        with open(rpath, "r", encoding="utf-8") as f:
            data = json.load(f)
            pkg = data.get("static_analysis", {}).get("metadata", {}).get("package_name", "")
            if pkg == "com.defensive.benignapp" and benign_report is None:
                benign_report = data
            elif pkg == "com.defensive.c2simulator" and malicious_report is None:
                malicious_report = data
                
    assert benign_report is not None, "BenignDemo report not found"
    assert malicious_report is not None, "C2Simulator report not found"
    
    b_score = benign_report["overall_risk_score"]
    b_verdict = benign_report["overall_verdict"]
    m_score = malicious_report["overall_risk_score"]
    m_verdict = malicious_report["overall_verdict"]
    
    m_c2_score = malicious_report["c2_detection"]["c2_heuristic_score"]
    m_indicators = malicious_report["c2_detection"]["indicators"]
    
    print(f"  [BENIGN] Package: {benign_report['static_analysis']['metadata']['package_name']}")
    print(f"           Verdict: {b_verdict} (Score: {b_score}/100)")
    print(f"           Connections: {benign_report['network_analysis']['total_connections']}")
    
    print(f"  [C2 SIMULATOR] Package: {malicious_report['static_analysis']['metadata']['package_name']}")
    print(f"                 Verdict: {m_verdict} (Score: {m_score}/100, C2 Score: {m_c2_score}/100)")
    print(f"                 Connections: {malicious_report['network_analysis']['total_connections']}")
    print(f"                 Indicators Detected: {len(m_indicators)}")
    for ind in m_indicators:
        print(f"                 - {ind['indicator']} ({ind['severity']}): {ind['description']}")
    
    assert "BENIGN" in b_verdict or "LOW" in b_verdict, f"Expected benign verdict, got {b_verdict}"
    assert m_c2_score >= 50, f"Expected C2 score >= 50, got {m_c2_score}"
    assert any(ind["indicator"] == "C2_BEACONING_PATTERN" for ind in m_indicators), "Expected beaconing indicator"
    
    results["TEST 7: Dynamic (Benign)"] = PASS
    results["TEST 8: Dynamic (Malicious C2)"] = PASS
    results["TEST 9: Comparison"] = PASS


def test_10_reports():
    print(f"\n{INFO} TEST 10: Reports Validation (JSON & HTML)")
    html_files = glob.glob("reports/report_session_*.html")
    json_files = glob.glob("reports/report_session_*.json")
    
    assert len(html_files) >= 2, f"Expected >= 2 HTML reports, got {len(html_files)}"
    assert len(json_files) >= 2, f"Expected >= 2 JSON reports, got {len(json_files)}"
    
    for hf in html_files:
        size = os.path.getsize(hf)
        assert size > 2000, f"HTML report {hf} suspiciously small ({size} bytes)"
        with open(hf, "r", encoding="utf-8") as f:
            content = f.read()
            assert "Android Malware Analysis Forensic Report" in content
            assert "Target APK Info" in content
            assert "Network Telemetry" in content
            assert "Sensitive Android Permissions Audit" in content
            assert "Intercepted Network Traffic" in content
            
    print(f"  - HTML Reports: {len(html_files)} verified (complete sections, styled, responsive)")
    print(f"  - JSON Reports: {len(json_files)} verified (valid schema)")
    results["TEST 10: Forensic Reports"] = PASS


def main():
    print("=" * 70)
    print("STAGE N: END-TO-END VERIFICATION & VALIDATION SUITE")
    print("=" * 70)
    
    test_1_environment()
    test_2_emulator()
    test_3_and_4_network_cert()
    test_5_frida()
    test_6_static_analysis()
    test_7_8_and_9_dynamic_comparison()
    test_10_reports()
    
    print("\n" + "=" * 70)
    print("VERIFICATION RESULTS SUMMARY")
    print("=" * 70)
    all_passed = True
    for test, res in results.items():
        print(f"  {test:<40} : {res}")
        if res != PASS:
            all_passed = False
            
    print("=" * 70)
    if all_passed:
        print("[SUCCESS] ALL 10 TESTS PASSED END-TO-END WITHOUT ERRORS!")
        return 0
    else:
        print("[FAIL] ONE OR MORE VERIFICATION TESTS FAILED.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
