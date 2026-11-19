import hashlib
import os
import zipfile
from pathlib import Path
from fastapi import HTTPException, UploadFile

MAX_APK_BYTES = 200 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 20_000


def hash_file(file_path: str) -> dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


async def save_upload(file: UploadFile, dest: str, limit: int = MAX_APK_BYTES) -> int:
    size = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                out.close()
                if os.path.exists(dest):
                    os.remove(dest)
                raise HTTPException(413, "File exceeds the 200 MB limit.")
            out.write(chunk)
    return size


def validate_apk(path: str) -> None:
    if not zipfile.is_zipfile(path):
        raise ValueError("Not a valid APK/ZIP archive.")
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError("Archive has too many entries.")
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Archive expands beyond the allowed size.")
        names = {i.filename for i in infos}
        has_dex = any(n.startswith("classes") and n.endswith(".dex") for n in names)
        if "AndroidManifest.xml" not in names or not has_dex:
            raise ValueError("Missing AndroidManifest.xml or classes.dex.")


def extract_apk_securely(apk_path: str, extract_dir: str) -> dict:
    validate_apk(apk_path)
    dest = Path(extract_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    tree = set()
    with zipfile.ZipFile(apk_path) as zf:
        for member in zf.infolist():
            target = (dest / member.filename).resolve()
            if not target.is_relative_to(dest):
                raise ValueError(f"Unsafe path in archive: {member.filename}")
            zf.extract(member, dest)
            top = member.filename.split("/")[0]
            tree.add(top + "/" if (member.is_dir() or "/" in member.filename) else top)
    return {"extraction_dir": str(dest), "tree": sorted(tree)}
