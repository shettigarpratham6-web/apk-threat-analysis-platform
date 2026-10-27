"""
HTTPS Certificate Installer for Android Sandbox
Automates OpenSSL hash extraction from mitmproxy CA and installs the certificate
into the Android emulator system store (/system/etc/security/cacerts/).
"""

import os
import subprocess
import sys
from typing import Optional, Tuple
from colorama import init, Fore, Style

init(autoreset=True)


class CertificateInstaller:
    def __init__(
        self,
        openssl_bin: str = r"C:\Program Files\Git\usr\bin\openssl.exe",
        ca_cert_path: Optional[str] = None,
        adb_path: str = "adb"
    ):
        self.openssl_bin = openssl_bin
        self.ca_cert_path = ca_cert_path or os.path.expanduser(r"~/.mitmproxy/mitmproxy-ca-cert.pem")
        self.adb_path = adb_path

    def get_cert_hash(self) -> str:
        """Computes the subject_hash_old required by Android cacerts."""
        if not os.path.exists(self.ca_cert_path):
            raise FileNotFoundError(f"mitmproxy CA certificate not found at: {self.ca_cert_path}")
        
        cmd = [self.openssl_bin, "x509", "-inform", "PEM", "-subject_hash_old", "-in", self.ca_cert_path]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        cert_hash = res.stdout.strip().splitlines()[0]
        return cert_hash

    def prepare_cert_file(self, output_dir: str = "tools") -> Tuple[str, str]:
        """Creates the <hash>.0 file containing the certificate."""
        cert_hash = self.get_cert_hash()
        os.makedirs(output_dir, exist_ok=True)
        cert_filename = f"{cert_hash}.0"
        dest_path = os.path.join(output_dir, cert_filename)

        with open(self.ca_cert_path, "r", encoding="utf-8") as f_in, open(dest_path, "w", encoding="utf-8") as f_out:
            f_out.write(f_in.read())

        return cert_hash, dest_path

    def is_installed_in_emulator(self, cert_hash: str) -> bool:
        """Checks if the certificate is already present in /system/etc/security/cacerts/."""
        check_cmd = [self.adb_path, "shell", f"[ -f /system/etc/security/cacerts/{cert_hash}.0 ] && echo exists"]
        res = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return "exists" in res.stdout

    def install(self, output_dir: str = "tools") -> bool:
        """
        Installs the mitmproxy CA certificate into Android system store.
        Uses a tmpfs overlay mount to ensure non-destructive and 100% reliable write access.
        """
        print(f"\n{Fore.CYAN}[*] Starting System CA Certificate Installation...{Style.RESET_ALL}")
        try:
            cert_hash, host_cert_file = self.prepare_cert_file(output_dir)
            print(f"{Fore.BLUE}[i] Certificate subject hash: {cert_hash} ({host_cert_file}){Style.RESET_ALL}")

            # Step 1: Ensure adb root
            subprocess.run([self.adb_path, "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Step 2: Check if already present
            if self.is_installed_in_emulator(cert_hash):
                print(f"{Fore.GREEN}[+] Certificate {cert_hash}.0 is already installed in system cacerts store.{Style.RESET_ALL}")
                return True

            # Step 3: Setup tmpfs overlay on /system/etc/security/cacerts
            print(f"{Fore.CYAN}[*] Mounting writable overlay on /system/etc/security/cacerts...{Style.RESET_ALL}")
            setup_script = (
                "mkdir -p /data/local/tmp/cacerts_backup && "
                "cp /system/etc/security/cacerts/* /data/local/tmp/cacerts_backup/ 2>/dev/null && "
                "mount -t tmpfs tmpfs /system/etc/security/cacerts && "
                "cp /data/local/tmp/cacerts_backup/* /system/etc/security/cacerts/"
            )
            subprocess.run([self.adb_path, "shell", setup_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

            # Step 4: Push the new certificate into /system/etc/security/cacerts/
            dest_android = f"/system/etc/security/cacerts/{cert_hash}.0"
            print(f"{Fore.CYAN}[*] Pushing certificate to {dest_android}...{Style.RESET_ALL}")
            push_res = subprocess.run([self.adb_path, "push", host_cert_file, dest_android], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            print(f"{Fore.BLUE}[i] {push_res.stdout.strip()}{Style.RESET_ALL}")

            # Step 5: Set permissions and SELinux context
            subprocess.run([self.adb_path, "shell", f"chmod 644 {dest_android}"], check=True)
            subprocess.run([self.adb_path, "shell", f"chown root:root {dest_android}"], check=True)
            subprocess.run([self.adb_path, "shell", f"chcon u:object_r:system_file:s0 {dest_android}"], check=True)

            # Step 6: Verify
            if self.is_installed_in_emulator(cert_hash):
                print(f"{Fore.GREEN}[+] Certificate {cert_hash}.0 verified inside /system/etc/security/cacerts/!{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] Verification failed: {dest_android} not found.{Style.RESET_ALL}")
                return False

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Certificate installation failed: {e}{Style.RESET_ALL}")
            return False


if __name__ == "__main__":
    installer = CertificateInstaller()
    success = installer.install()
    sys.exit(0 if success else 1)
