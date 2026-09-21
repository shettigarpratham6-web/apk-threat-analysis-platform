# Sandbox Dynamic Analysis Environment

This directory contains configuration, Frida hooks, mitmproxy traffic interceptor scripts, and Android emulator management utilities for running untrusted APKs in an isolated environment.

> ⚠️ **Host-Native Execution Requirement:**  
> The Android Virtual Device (AVD emulator), Frida instrumentation server, and mitmproxy network tap run on the **host machine** (outside Docker) because Android hardware virtualization (KVM/HAXM) and ADB socket connections require host-level access. When running the platform via Docker Compose, launch the emulator on your host machine alongside the Dockerized backend and frontend containers.

---


## 📌 Prerequisites

Before initiating dynamic sandbox analysis, complete the following system setup:

### 1. Android SDK & Emulator Setup
Install the Android SDK Command-Line Tools, Emulator, and Platform-Tools (`adb`). Ensure `$ANDROID_HOME` or `%ANDROID_HOME%` is set in your system environment.

### 2. Create Android Virtual Device (AVD)
Create a dedicated AVD (API 33 recommended) named `threat_sandbox_avd`:
```bash
# Example AVD creation using avdmanager
avdmanager create avd -n threat_sandbox_avd -k "system-images;android-33;google_apis;x86_64"
```

To manually launch or test the emulator with clean snapshot settings:
```bash
emulator -avd threat_sandbox_avd -no-snapshot-save -no-window
```

### 3. Frida-Server Setup
Download matching `frida-server` binary for Android x86_64 from [Frida Releases](https://github.com/frida/frida/releases), push to AVD, and set execution permissions:
```bash
adb push frida-server-16.x.x-android-x86_64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### 4. mitmproxy Interception Setup
Install `mitmproxy` on the host machine and configure AVD proxy settings to route HTTP/HTTPS traffic through `127.0.0.1:8080`. Push mitmproxy CA certificate to Android system credentials store for SSL unpinning.

---

## 📁 Directory Layout

```
sandbox/
├── emulator_config.py       # Configuration constants (AVD name, binary path, snapshot settings)
├── frida_scripts/           # Frida dynamic hooking JS scripts (crypto, network, SMS, API tracing)
├── mitmproxy_config/        # mitmproxy addon scripts and CA certificates
├── emulator_config/         # Shell setup scripts
└── README.md                # Sandbox documentation
```
