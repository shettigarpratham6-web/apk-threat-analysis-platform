# How Static Analysis Works

## How an APK Becomes Readable
An Android Package (APK) is fundamentally a ZIP archive. To analyze it, we must first extract it.

`suspicious_app.apk`
↓ unzip
- `AndroidManifest.xml`: Compiled binary XML describing the app.
- `classes.dex`: Compiled Java/Kotlin bytecode.
- `resources.arsc`: Compiled resource mapping.
- `res/`: XML layouts, icons, embedded configurations.
- `assets/`: Raw files like JSON config, API endpoints, Firebase configs.
- `lib/`: Native ARM libraries (`.so` files).

### AndroidManifest.xml
This file is parsed to extract permissions, activities, services, receivers, and intent filters. We identify exposed components and risky configurations (e.g., debuggable=true).

### classes.dex
Decompiled using `jadx` to Java source code. The Java code is then statically scanned to detect:
- Suspicious API calls (e.g., `Runtime.exec`, Reflection, Crypto usage)
- Hardcoded Strings (URLs, IP addresses)
- Dynamic loading behaviors

### res/ & assets/
Scanned for sensitive embedded information, such as API keys, Google Maps keys, Firebase configuration JSONs, or other plaintext secrets.

### lib/
Native libraries are checked for architecture, JNI (Java Native Interface) usage, and cross-referenced with known malware signatures (via hashing and YARA).

## Current Extraction Logic (`apk_loader.py` & `apk_extractor.py`)
Our backend accepts the uploaded APK and securely unzips it into a unique, temporary directory while preventing path traversal (ZIP Slip). After extraction, it iterates through the directory tree and pipes specific file types (like `.dex` and `AndroidManifest.xml`) into their respective analysis modules.
