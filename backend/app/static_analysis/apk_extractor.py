"""Module for secure APK extraction."""

import os
import zipfile
import hashlib
from typing import Dict, Any, List

def hash_file(file_path: str) -> Dict[str, str]:
    """Calculate SHA256 and MD5 hashes of a file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest()
    }

def extract_apk_securely(apk_path: str, extract_dir: str) -> Dict[str, Any]:
    """
    Extracts an APK securely into a target directory preventing ZIP Slip.
    Returns the extraction directory tree.
    """
    os.makedirs(extract_dir, exist_ok=True)
    tree_set = set()
    
    if not zipfile.is_zipfile(apk_path):
        raise ValueError("Provided file is not a valid APK/ZIP archive.")
        
    with zipfile.ZipFile(apk_path, "r") as zf:
        for member in zf.infolist():
            # ZIP slip prevention
            member_path = os.path.abspath(os.path.join(extract_dir, member.filename))
            if not member_path.startswith(os.path.abspath(extract_dir)):
                continue # Skip unsafe extraction
            
            # Extract
            zf.extract(member, extract_dir)
            
            # Build simple tree representation
            parts = member.filename.split('/')
            if len(parts) > 0:
                top_level = parts[0]
                if member.is_dir():
                    tree_set.add(top_level + '/')
                else:
                    if len(parts) == 1:
                        tree_set.add(top_level)
                    else:
                        tree_set.add(top_level + '/')
                        
    return {
        "extraction_dir": extract_dir,
        "tree": sorted(list(tree_set))
    }
