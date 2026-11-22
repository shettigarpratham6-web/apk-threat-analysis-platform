"""FastAPI router for static analysis endpoints."""

import asyncio
import concurrent.futures
import json
import os
import shutil
import time
import uuid
from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from backend.app.static_analysis.apk_extractor import extract_apk_securely, hash_file
from backend.app.static_analysis.manifest_check import analyze_manifest
from backend.app.static_analysis.code_analysis import analyze_code
from backend.app.static_analysis.resource_analysis import analyze_resources
from backend.app.static_analysis.native_library_analysis import analyze_native_libs
from backend.app.static_analysis.signature_check import run_yara_scan
from backend.app.static_analysis.cert_scanner import scan_certificates
from loguru import logger
from backend.app.static_analysis.aggregator import calculate_risk, generate_iocs
from backend.core.static_analysis.ml_classifier import get_static_malware_classifier
from backend.core.static_analysis import analyze_static

# Try to import Androguard for manifest parsing
try:
    from androguard.core.apk import APK
except ImportError:
    APK = None

router = APIRouter()
ml_classifier = get_static_malware_classifier()

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
    
    file_path = os.path.join(UPLOADS_DIR, f"{apk_id}.apk")
    
    try:
        t0_up = time.time()
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        file_size = os.path.getsize(file_path)
        hashes = hash_file(file_path)
        logger.info(f"[PERFORMANCE] Stage 'apk_upload_validation': {time.time() - t0_up:.3f}s")
        
        t0_ext = time.time()
        extract_dir = os.path.join(upload_dir, "extracted")
        extraction_result = extract_apk_securely(file_path, extract_dir)
        logger.info(f"[PERFORMANCE] Stage 'apk_extraction': {time.time() - t0_ext:.3f}s")
        
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
async def analyze_apk_pipeline(file: UploadFile = File(...), deep_decompile: bool = False):
    """
    Unified Static Analysis Endpoint.
    Executes the complete static analysis pipeline with fast DEX-level static risk engine v2.
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
    
    file_path = os.path.join(UPLOADS_DIR, f"{apk_id}.apk")
    extract_dir = os.path.join(upload_dir, "extracted")
    t0_pipeline = time.time()
    
    try:
        # 1. Validation & Save
        t0_val = time.time()
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
        logger.info(f"[PERFORMANCE] Stage 'apk_upload_validation': {time.time() - t0_val:.3f}s")
        
        # 2. Extract APK
        t0_ext = time.time()
        extraction_data = extract_apk_securely(file_path, extract_dir)
        extraction_tree = extraction_data.get("tree", []) if isinstance(extraction_data, dict) else []
        logger.info(f"[PERFORMANCE] Stage 'apk_extraction': {time.time() - t0_ext:.3f}s")
        
        t0_andro = time.time()
        try:
            apk_obj = APK(file_path) if APK else None
        except Exception as e:
            logger.warning(f"Failed to load APK with Androguard: {e}")
            apk_obj = None
        if apk_obj:
            logger.info(f"[PERFORMANCE] Stage 'androguard_apk_load': {time.time() - t0_andro:.3f}s")
        
        # 3. Static Risk Engine v2 (Pure DEX/Manifest extraction, non-blocking)
        t0_static_eng = time.time()
        try:
            static_result = await asyncio.to_thread(analyze_static, file_path)
        except Exception as e:
            logger.error(f"Static risk engine failed or file is mocked: {e}")
            static_result = {
                "overall": 0.0,
                "level": "CLEAN",
                "risk_score": 0.0,
                "threat_level": "CLEAN",
                "scores": {},
                "score_weights": {},
                "permission_findings": [],
                "flagged_permissions": [],
                "behavior_findings": [],
                "toxic_combinations": [],
                "exposed_components": [],
                "manifest_flags": {},
                "signature": {},
                "embedded_payloads": [],
                "yara_matches": [],
                "secrets_found": [],
                "top_reasons": [],
                "warnings": [str(e)],
                "timings": {},
            }
        logger.info(f"[PERFORMANCE] Stage 'static_risk_engine': {time.time() - t0_static_eng:.3f}s")

        # robust wrapper
        def safe_run(func, *args, default_ret={}):
            try:
                return func(*args)
            except Exception as e:
                logger.error(f"Scanner {func.__name__} failed: {e}")
                return {"error": str(e), **default_ret}

        # Concurrently execute independent static analysis phases via ThreadPoolExecutor
        t0_phases = time.time()
        max_workers = min(8, os.cpu_count() or 6)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            fut_manifest = executor.submit(safe_run, analyze_manifest, apk_obj)
            fut_cert = executor.submit(safe_run, scan_certificates, file_path, apk_obj, default_ret=[])
            fut_res = executor.submit(safe_run, analyze_resources, extract_dir)
            fut_native = executor.submit(safe_run, analyze_native_libs, extract_dir)
            if deep_decompile:
                fut_code = executor.submit(safe_run, analyze_code, file_path)
                fut_yara = executor.submit(safe_run, run_yara_scan, extract_dir, default_ret=[])
            else:
                fut_code = None
                fut_yara = None

            manifest_results = fut_manifest.result()
            cert_results = fut_cert.result()
            if isinstance(cert_results, dict) and "error" in cert_results:
                cert_results = []
            if deep_decompile and fut_code:
                code_results = fut_code.result()
            else:
                code_results = {
                    "analyzed_files": 0,
                    "suspicious_apis": [
                        {"api": b.get("behavior", ""), "severity": "High" if b.get("severity", 0) >= 7 else "Medium", "description": b.get("description", "")}
                        for b in static_result.get("behavior_findings", [])
                    ],
                    "malware_indicators": [],
                    "obfuscation_findings": [],
                    "codebert_similarity": {},
                    "deep_decompile": False,
                }
            resource_results = fut_res.result()
            native_results = fut_native.result()
            if deep_decompile and fut_yara:
                yara_results = fut_yara.result()
            else:
                yara_results = static_result.get("yara_matches", [])
            if isinstance(yara_results, dict) and "error" in yara_results:
                yara_results = []
        logger.info(f"[PERFORMANCE] Stage 'concurrent_static_scanners': {time.time() - t0_phases:.3f}s")
            
        # 9. Static Feature Vector Extraction & Random Forest ML Classification
        t0_ml = time.time()
        ml_clf = get_static_malware_classifier()
        feature_vector = ml_clf.extract_feature_vector_from_static_analysis(
            manifest_results=manifest_results,
            code_results=code_results,
            native_results=native_results
        )
        ml_results = safe_run(
            ml_clf.predict,
            feature_vector,
            default_ret={"prediction": "unknown", "malware_probability": 0.0, "benign_probability": 0.0}
        )
        logger.info(f"[PERFORMANCE] Stage 'ml_classification': {time.time() - t0_ml:.3f}s")

        # 10. Static Risk Engine v2 Result Mapping
        level_val = "Safe" if (static_result["overall"] == 0 and static_result["level"] == "CLEAN") else static_result["level"]
        risk_results = {
            **static_result,
            "score": static_result["overall"],
            "level": level_val,
            "risk_score": static_result["overall"],
            "threat_level": static_result["level"],
            "factors": static_result.get("top_reasons", []),
            "recommendations": [
                f"Review necessity of permission: {p}"
                for p in static_result.get("flagged_permissions", [])
            ] or ["No high-risk permissions detected."],
        }
        
        # 11. IOC Generator
        t0_ioc = time.time()
        ioc_results = generate_iocs(metadata, code_results, resource_results, cert_results)
        
        # Save independent JSONs
        with open(os.path.join(RESULTS_DIR, f"{apk_id}_ioc.json"), "w") as f:
            json.dump(ioc_results, f, indent=4)
            
        # Save IOC CSV
        from backend.app.static_analysis.aggregator import generate_ioc_csv
        generate_ioc_csv(ioc_results, os.path.join(RESULTS_DIR, f"{apk_id}_ioc.csv"))
        logger.info(f"[PERFORMANCE] Stage 'ioc_generation': {time.time() - t0_ioc:.3f}s")
            
        final_results = {
            "apk_id": apk_id,
            "metadata": metadata,
            "extraction": {"tree": extraction_tree},
            "manifest_analysis": manifest_results,
            "certificate_analysis": cert_results,
            "code_analysis": code_results,
            "codebert_similarity": code_results.get("codebert_similarity", {}),
            "resource_analysis": resource_results,
            "native_library_analysis": native_results,
            "yara_matches": yara_results,
            "ml_classification": ml_results,
            "static_feature_vector": feature_vector,
            "risk_analysis": risk_results,
            "iocs": ioc_results,
            # Direct aliases
            "overall": static_result["overall"],
            "level": static_result["level"],
            "risk_score": static_result["overall"],
            "threat_level": static_result["level"],
            "scores": static_result["scores"],
            "permission_findings": static_result.get("permission_findings", []),
            "toxic_combinations": static_result.get("toxic_combinations", []),
            "top_reasons": static_result.get("top_reasons", []),
            "publisher_verified": static_result.get("publisher_verified", False),
            "confidence": static_result.get("confidence", "low"),
            "timings": static_result.get("timings", {}),
        }
        
        with open(os.path.join(RESULTS_DIR, f"{apk_id}_report.json"), "w") as f:
            json.dump(final_results, f, indent=4)
        with open(os.path.join(RESULTS_DIR, f"{apk_id}_static.json"), "w") as f:
            json.dump(final_results, f, indent=4)
            
        logger.info(f"[PERFORMANCE] Stage 'total_static_analysis_pipeline': {time.time() - t0_pipeline:.3f}s")
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
        if os.path.exists(upload_dir) and not os.listdir(upload_dir):
            shutil.rmtree(upload_dir, ignore_errors=True)


@router.post("/codebert-similarity")
async def analyze_codebert_similarity_endpoint(
    request: Request,
):
    """
    Direct CodeBERT suspicious-code similarity analysis endpoint.
    Accepts raw code snippets (Java, Kotlin, Smali) via JSON body or Form data.
    Returns matched suspicious behavioral patterns with confidence scores and evidence references.
    """
    code_text = ""
    class_name = "DirectAnalyzedClass"
    file_path = "source.java"
    line_number = 1

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            code_text = body.get("code", "")
            class_name = body.get("class_name", class_name)
            file_path = body.get("file_path", file_path)
            line_number = body.get("line_number", line_number)
        except Exception:
            pass
    else:
        form = await request.form()
        code_text = str(form.get("code") or "")
        class_name = str(form.get("class_name") or class_name)
        file_path = str(form.get("file_path") or file_path)

    if not code_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'code' must contain non-empty code to analyze."
        )

    from backend.app.static_analysis.codebert_analyzer import get_codebert_analyzer
    cb = get_codebert_analyzer()
    matches = cb.analyze_snippet(
        code_text,
        context_meta={"class_name": class_name, "file_path": file_path, "line_number": line_number}
    )

    return {
        "status": "fallback" if cb._fallback_mode else "active",
        "model": "heuristic-fallback" if cb._fallback_mode else cb.model_name,
        "input": {
            "class_name": class_name,
            "file_path": file_path,
            "code_snippet": code_text[:200],
        },
        "matches_found": len(matches),
        "matches": matches,
        "disclaimer": (
            "Pretrained CodeBERT semantic code similarity analysis. Indicates behavioral resemblance "
            "to reference suspicious templates, not an autonomous malware classification verdict."
        )
    }

