# Tools Directory

This directory stores external utility binaries, scripts, and pre-compiled tools required for both static and dynamic analysis:

### Static Analysis Tools
1. **`apktool`**:
   - `apktool.jar` for local APK extraction, resource decoding, and decompilation without requiring a global installation.

2. **`jadx`**:
   - Decompiler (`jadx` / `jadx-gui`) located in `tools/jadx/` for decompiling Android DEX and APK files to readable Java source code.

### Dynamic Sandbox Tools
1. **`frida-server`**:
   - The Frida server binary architecture matching the Android emulator (`frida-server-<version>-android-x86_64`).
   - Pushed dynamically during sandbox initialization to `/data/local/tmp/frida-server` on the emulator.

2. **Certificate Utilities**:
   - Pre-generated or custom Android system CA certificate `<hash>.0` (e.g. `c8750f0d.0`) derived from `mitmproxy-ca-cert.pem`.

3. **Keystore**:
   - `debug.keystore` for signing modified or re-packaged APKs if necessary.

All third-party binaries placed here should be tagged with their respective versions and verified against the host client tools.
