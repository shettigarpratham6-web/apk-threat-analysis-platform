"""
Automated Test APK Generator
Builds genuine, signed Android APKs for sandbox testing:
1. BenignDemo.apk (datasets/benign/BenignDemo.apk)
2. C2Simulator.apk (datasets/malicious/C2Simulator.apk) - Harmless C2 beacon simulator
"""

import os
import shutil
import subprocess
import zipfile
from typing import Dict, Any, List
from colorama import init, Fore, Style

init(autoreset=True)

BUILD_TOOLS_DIR = r"C:\Users\UJWAL\AppData\Local\Android\Sdk\build-tools\36.0.0"
ANDROID_JAR = r"C:\Users\UJWAL\AppData\Local\Android\Sdk\platforms\android-37.0\android.jar"
KEYTOOL_EXE = r"C:\Program Files\Android\Android Studio\jbr\bin\keytool.exe"
AAPT_EXE = os.path.join(BUILD_TOOLS_DIR, "aapt.exe")
D8_BAT = os.path.join(BUILD_TOOLS_DIR, "d8.bat")
APKSIGNER_BAT = os.path.join(BUILD_TOOLS_DIR, "apksigner.bat")
KEYSTORE_PATH = os.path.abspath(r"tools\debug.keystore")


class APKBuilder:
    def __init__(self):
        os.environ["SKIP_JDK_VERSION_CHECK"] = "true"
        self._ensure_keystore()

    def _ensure_keystore(self):
        """Generates a standard Android debug keystore if not already present."""
        if not os.path.exists(KEYSTORE_PATH):
            print(f"{Fore.CYAN}[*] Generating debug signing keystore: {KEYSTORE_PATH}...{Style.RESET_ALL}")
            os.makedirs(os.path.dirname(KEYSTORE_PATH), exist_ok=True)
            cmd = [
                KEYTOOL_EXE, "-genkeypair", "-v",
                "-keystore", KEYSTORE_PATH,
                "-alias", "androiddebugkey",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-storepass", "android",
                "-keypass", "android",
                "-dname", "CN=Android Debug,O=Android,C=US"
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"{Fore.GREEN}[+] Debug keystore created successfully.{Style.RESET_ALL}")

    def build_apk(
        self,
        package_name: str,
        app_name: str,
        activity_source: str,
        manifest_xml: str,
        output_apk: str
    ) -> str:
        """Compiles, packages, and signs an Android APK."""
        build_dir = os.path.abspath(f"tools\\build_{package_name.replace('.', '_')}")
        src_dir = os.path.join(build_dir, "src")
        bin_dir = os.path.join(build_dir, "bin")

        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)
        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(bin_dir, exist_ok=True)

        package_path = os.path.join(src_dir, *package_name.split("."))
        os.makedirs(package_path, exist_ok=True)

        # 1. Write Manifest
        manifest_path = os.path.join(build_dir, "AndroidManifest.xml")
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest_xml)

        # 2. Write Java Source
        java_file = os.path.join(package_path, "MainActivity.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write(activity_source)

        print(f"{Fore.CYAN}[*] Compiling Java sources for {package_name}...{Style.RESET_ALL}")
        javac_cmd = [
            "javac", "--release", "8",
            "-cp", ANDROID_JAR,
            "-d", bin_dir,
            java_file
        ]
        subprocess.run(javac_cmd, check=True)

        # 3. Compile to classes.dex using D8
        print(f"{Fore.CYAN}[*] Generating classes.dex with D8...{Style.RESET_ALL}")
        class_files = []
        for root, _, files in os.walk(bin_dir):
            for file in files:
                if file.endswith(".class"):
                    class_files.append(os.path.join(root, file))

        d8_cmd = [D8_BAT, "--output", build_dir] + class_files
        subprocess.run(d8_cmd, check=True, stdout=subprocess.PIPE)
        dex_path = os.path.join(build_dir, "classes.dex")

        # 4. Package resources and manifest with aapt
        raw_apk = os.path.join(build_dir, "unaligned.apk")
        print(f"{Fore.CYAN}[*] Packaging APK resources with aapt...{Style.RESET_ALL}")
        aapt_cmd = [
            AAPT_EXE, "package", "-f", "-m",
            "-F", raw_apk,
            "-M", manifest_path,
            "-I", ANDROID_JAR
        ]
        subprocess.run(aapt_cmd, check=True, stdout=subprocess.PIPE)

        # 5. Add classes.dex into the APK
        with zipfile.ZipFile(raw_apk, "a") as z:
            z.write(dex_path, "classes.dex")

        # 6. Sign the APK using apksigner
        os.makedirs(os.path.dirname(os.path.abspath(output_apk)), exist_ok=True)
        shutil.copy2(raw_apk, output_apk)

        print(f"{Fore.CYAN}[*] Signing APK with debug certificate...{Style.RESET_ALL}")
        sign_cmd = [
            APKSIGNER_BAT, "sign",
            "--ks", KEYSTORE_PATH,
            "--ks-pass", "pass:android",
            "--key-pass", "pass:android",
            output_apk
        ]
        subprocess.run(sign_cmd, check=True, stdout=subprocess.PIPE)

        # Clean build directory
        shutil.rmtree(build_dir, ignore_errors=True)
        print(f"{Fore.GREEN}[+] APK successfully built & signed: {output_apk}{Style.RESET_ALL}")
        return output_apk

    def build_benign_app(self, dest: str = "datasets/benign/BenignDemo.apk") -> str:
        """Builds a benign test application."""
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.defensive.benignapp"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:label="Benign Demo"
        android:allowBackup="true"
        android:supportsRtl="true">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""

        java = """package com.defensive.benignapp;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("Benign Research Test Application - Clean Baseline");
        setContentView(tv);
    }
}"""
        return self.build_apk("com.defensive.benignapp", "Benign Demo", java, manifest, dest)

    def build_c2_simulator_app(self, dest: str = "datasets/malicious/C2Simulator.apk") -> str:
        """
        Builds a harmless C2 behavior simulator application.
        Simulates periodic HTTP beaconing to the local host sandbox proxy (10.0.2.2:8080/api/beacon).
        Does NOT perform any destructive or real malicious operations.
        """
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.defensive.c2simulator"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <application
        android:label="C2 Simulator"
        android:allowBackup="true"
        android:supportsRtl="true">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""

        java = """package com.defensive.c2simulator;

import android.app.Activity;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.util.Log;
import android.widget.TextView;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends Activity {
    private static final String TAG = "C2Simulator";
    private volatile boolean isRunning = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("C2 Beacon Simulator - Automated Research Test App");
        setContentView(tv);

        // Start harmless periodic beacon simulation thread
        new Thread(new Runnable() {
            @Override
            public void run() {
                // Send simulated observational SMS once to test hook_sms.js
                try {
                    SmsManager sms = SmsManager.getDefault();
                    sms.sendTextMessage("5554", null, "C2_STATUS_CHECKIN", null, null);
                } catch (Exception se) {
                    Log.d(TAG, "SMS test notice: " + se.getMessage());
                }

                int pingCount = 0;
                while (isRunning && pingCount < 6) {
                    try {
                        pingCount++;
                        Log.i(TAG, "Simulating C2 beacon checkin #" + pingCount);
                        URL url = new URL("http://example.com/api/beacon?client_id=sim_device_01&seq=" + pingCount);
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestMethod("GET");
                        conn.setConnectTimeout(4000);
                        conn.setReadTimeout(4000);
                        int respCode = conn.getResponseCode();
                        Log.i(TAG, "Beacon response code: " + respCode);
                        conn.disconnect();
                    } catch (Exception e) {
                        Log.w(TAG, "Beacon simulation connection: " + e.getMessage());
                    }

                    try {
                        // Strict 3-second interval simulation for rapid lab testing
                        Thread.sleep(3000);
                    } catch (InterruptedException ie) {
                        break;
                    }
                }
            }
        }).start();
    }

    @Override
    protected void onDestroy() {
        isRunning = false;
        super.onDestroy();
    }
}"""
        return self.build_apk("com.defensive.c2simulator", "C2 Simulator", java, manifest, dest)


if __name__ == "__main__":
    builder = APKBuilder()
    benign = builder.build_benign_app()
    malicious = builder.build_c2_simulator_app()
    print(f"\n{Fore.GREEN}=== TEST APKS READY ==={Style.RESET_ALL}")
    print(f"Benign APK   : {benign} ({os.path.getsize(benign)} bytes)")
    print(f"Simulator APK: {malicious} ({os.path.getsize(malicious)} bytes)")
