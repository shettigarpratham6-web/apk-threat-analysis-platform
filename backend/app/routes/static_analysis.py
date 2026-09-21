"""FastAPI router for static analysis endpoints."""

import json
import os
import shutil
import uuid
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.static_analysis.apk_extractor import extract_apk_securely, hash_file
from backend.app.static_analysis.manifest_check import analyze_manifest
from backend.app.static_analysis.code_analysis import analyze_code
from backend.app.static_analysis.resource_analysis import analyze_resources
from backend.app.static_analysis.native_library_analysis import analyze_native_libs
from backend.app.static_analysis.signature_check import run_yara_scan
from backend.app.static_analysis.cert_scanner import scan_certificates
from backend.app.static_analysis.aggregator import calculate_risk, generate_iocs

# Try to import Androguard for manifest parsing
try:
    from androguard.core.apk import APK
except ImportError:
    APK = None

router = APIRouter()

UPLOADS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "uploads"))
RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


@router.post("/upload")
async def upload_and_analyze_apk(file: UploadFile = File(...)):
    """
    Accepts an uploaded APK file, validates, hashes, securely extracts it,
    and returns metadata + extraction tree.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Please upload a valid .apk file.",
        )

    apk_id = str(uuid.uuid4())
    upload_dir = os.path.join(UPLOADS_DIR, apk_id)
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, "original.apk")
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        file_size = os.path.getsize(file_path)
        hashes = hash_file(file_path)
        
        extract_dir = os.path.join(upload_dir, "extracted")
        extraction_result = extract_apk_securely(file_path, extract_dir)
        
        return {
            "apk_id": apk_id,
            "metadata": {
                "sha256": hashes["sha256"],
                "md5": hashes["md5"],
                "size": file_size,
                "filename": file.filename
            },
            "extraction": extraction_result
        }
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))


@router.post("/analyze")
async def analyze_apk_pipeline(file: UploadFile = File(...)):
    """
    Unified Static Analysis Endpoint.
    Executes the complete static analysis pipeline (Phases 1-9).
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file format. Please upload a valid .apk file.")
        
    if file.content_type not in ["application/vnd.android.package-archive", "application/octet-stream", "application/zip", "application/x-zip-compressed"]:
        # Basic MIME validation
        pass
        
    apk_id = str(uuid.uuid4())
    upload_dir = os.path.join(UPLOADS_DIR, apk_id)
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    file_path = os.path.join(upload_dir, "original.apk")
    extract_dir = os.path.join(upload_dir, "extracted")
    
    try:
        # 1. Validation & Save
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        file_size = os.path.getsize(file_path)
        if file_size > 200 * 1024 * 1024:
            os.remove(file_path)
            raise HTTPException(status_code=413, detail="File exceeds the 200MB limit.")
        hashes = hash_file(file_path)
        metadata = {
            "filename": file.filename,
            "size": file_size,
            "sha256": hashes["sha256"],
            "md5": hashes["md5"]
        }
        
        # 2. Extract APK
        extraction_data = extract_apk_securely(file_path, extract_dir)
        extraction_tree = extraction_data.get("tree", [])
        
        apk_obj = APK(file_path) if APK else None
        
        # robust wrapper
        def safe_run(func, *args, default_ret={}):
            try:
                return func(*args)
            except Exception as e:
                logger.error(f"Scanner {func.__name__} failed: {e}")
                return {"error": str(e), **default_ret}

        # 3. AndroidManifest.xml Analysis
        manifest_results = safe_run(analyze_manifest, apk_obj)
        
        # 4. Certificate Scanning
        cert_results = safe_run(scan_certificates, file_path, default_ret=[])
        if isinstance(cert_results, dict) and "error" in cert_results:
            cert_results = []
            
        # 5. DEX Code Analysis (Jadx/Apktool + Entropy)
        code_results = safe_run(analyze_code, file_path)
        
        # 6. Resource Analysis (Secrets)
        resource_results = safe_run(analyze_resources, extract_dir)
        
        # 7. Native Library Analysis
        native_results = safe_run(analyze_native_libs, extract_dir)
        
        # 8. YARA Signature Scanner
        yara_results = safe_run(run_yara_scan, extract_dir, default_ret=[])
        if isinstance(yara_results, dict) and "error" in yara_results:
            yara_results = []
            
        # 9. Risk Correlation Engine
        risk_results = calculate_risk(
            manifest_results, 
            code_results, 
            resource_results, 
            native_results, 
            yara_results,
            cert_results
        )
        
        # 10. IOC Generator
        ioc_results = generate_iocs(metadata, code_results, resource_results, cert_results)
        
        # Save independent JSONs
        with open(os.path.join(RESULTS_DIR, f"{apk_id}_ioc.json"), "w") as f:
            json.dump(ioc_results, f, indent=4)
            
        # Save IOC CSV
        from backend.app.static_analysis.aggregator import generate_ioc_csv
        generate_ioc_csv(ioc_results, os.path.join(RESULTS_DIR, f"{apk_id}_ioc.csv"))
            
        final_results = {
            "apk_id": apk_id,
            "metadata": metadata,
            "extraction": {"tree": extraction_tree},
            "manifest_analysis": manifest_results,
            "certificate_analysis": cert_results,
            "code_analysis": code_results,
            "resource_analysis": resource_results,
            "native_library_analysis": native_results,
            "yara_matches": yara_results,
            "risk_analysis": risk_results,
            "iocs": ioc_results
        }
        
        with open(os.path.join(RESULTS_DIR, f"{apk_id}_report.json"), "w") as f:
            json.dump(final_results, f, indent=4)
            
        return final_results
        
    except HTTPException:
        raise
    except Exception as err:
        logger.error(f"Unexpected error in pipeline: {err}")
        raise HTTPException(status_code=500, detail=f"Pipeline crashed: {str(err)}")
    finally:
        # Cleanup temporary extracted files to prevent disk exhaustion
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
        if os.path.exists(file_path):
            os.remove(file_path)
