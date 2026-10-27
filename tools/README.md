# Tools Directory

This directory stores external utility binaries, scripts, and pre-compiled agents required by the sandbox:

1. **`frida-server`**:
   - The Frida server binary architecture matching the Android emulator (`frida-server-<version>-android-x86_64`).
   - Pushed dynamically during sandbox initialization to `/data/local/tmp/frida-server` on the emulator.

2. **Certificate Utilities**:
   - Hash generation scripts for converting the `mitmproxy-ca-cert.pem` into an Android system CA certificate `<hash>.0`.

All third-party binaries placed here should be tagged with their respective versions and verified against the host client tools.
