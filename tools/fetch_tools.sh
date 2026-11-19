#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APKTOOL_VERSION="2.9.3"
APKTOOL_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
APKTOOL_SHA256="7956eb04194300ce0d0a84ad18771eebc94b89fb8d1ddcce8ea4c056818646f4"

JADX_VERSION="1.4.7"
JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
JADX_SHA256="a13d2be02ed640de54df937ead680f31ea06f4b8efd01860b9f0cf18a7d40e34"

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        echo "Error: sha256sum or shasum required for hash verification." >&2
        exit 1
    fi

    if [ "$actual" != "$expected" ]; then
        echo "Hash mismatch for $file:" >&2
        echo "  Expected: $expected" >&2
        echo "  Actual:   $actual" >&2
        exit 1
    fi
}

echo "Downloading apktool v${APKTOOL_VERSION}..."
curl -sSL "$APKTOOL_URL" -o "apktool.jar"
verify_sha256 "apktool.jar" "$APKTOOL_SHA256"
echo "Apktool verified successfully."

echo "Downloading jadx v${JADX_VERSION}..."
curl -sSL "$JADX_URL" -o "jadx.zip"
verify_sha256 "jadx.zip" "$JADX_SHA256"
echo "Jadx zip verified successfully."

rm -rf jadx
mkdir -p jadx
unzip -q jadx.zip -d jadx
rm -f jadx.zip
chmod +x jadx/bin/jadx jadx/bin/jadx-gui || true
echo "Jadx extracted successfully."
