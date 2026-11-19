"""FastAPI router for static analysis endpoints."""

import concurrent.futures
import json
import os
import shutil
import uuid
from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from backend.app.static_analysis.apk_extractor import extract_apk_securely, hash_file, save_upload
from backend.app.static_analysis.manifest_check import analyze_manifest
from backend.app.static_analysis.code_analysis import analyze_code
from backend.app.static_analysis.resource_analysis import analyze_resources
from backend.app.static_analysis.native_library_analysis import analyze_native_libs
from backend.app.static_analysis.signature_check import run_yara_scan
from backend.app.static_analysis.cert_scanner import scan_certificates
from loguru import logger
from backend.app.static_analysis.aggregator import calculate_risk, generate_iocs
from backend.app.static_analysis.ml_classifier import get_static_malware_classifier

_MISSING = object()


def safe_run(func, *args, default=_MISSING):
    try:
        return func(*args)
    except Exception as e:
        scanner_name = getattr(func, "__name__", str(func))
        logger.error(f"Scanner {scanner_name} failed: {e}")
        return {"error": str(e)} if default is _MISSING else default

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
        file_size = await save_upload(file, file_path)
        hashes = hash_file(file_path)
        extract_dir = os.path.join(upload_dir, "extracted")
        extraction_result = extract_apk_securely(file_path, extract_dir)
        return {
            "apk_id": apk_id,
            "metadata": {
                "sha256": hashes["sha256"],
                "md5": hashes["md5"],
                "size": file_size,
                "filename": file.filename,
            },
            "extraction": extraction_result,
        }
    except HTTPException:
        raise
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except Exception:
        logger.exception("Upload processing failed")
        raise HTTPException(status_code=500, detail="Internal server error during upload.")


@router.post("/analyze")
async def analyze_apk_pipeline(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file format. Please upload a valid .apk file.")

    apk_id = str(uuid.uuid4())
    upload_dir = os.path.join(UPLOADS_DIR, apk_id)
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    file_path = os.path.join(upload_dir, "original.apk")
    extract_dir = os.path.join(upload_dir, "extracted")

    try:
        file_size = await save_upload(file, file_path)
        hashes = hash_file(file_path)
        metadata = {
            "filename": file.filename,
            "size": file_size,
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
        }
        extraction_data = extract_apk_securely(file_path, extract_dir)
        extraction_tree = extraction_data.get("tree", []) if isinstance(extraction_data, dict) else []

        try:
            apk_obj = APK(file_path) if APK else None
        except Exception as e:
            logger.warning(f"Failed to load APK with Androguard: {e}")
            apk_obj = None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            fut_manifest = executor.submit(safe_run, analyze_manifest, apk_obj)
            fut_cert = executor.submit(safe_run, scan_certificates, file_path, default=[])
            fut_code = executor.submit(safe_run, analyze_code, file_path)
            fut_res = executor.submit(safe_run, analyze_resources, extract_dir)
            fut_native = executor.submit(safe_run, analyze_native_libs, extract_dir)
            fut_yara = executor.submit(safe_run, run_yara_scan, extract_dir, default=[])

            manifest_results = fut_manifest.result()
            cert_results = fut_cert.result()
            code_results = fut_code.result()
            resource_results = fut_res.result()
            native_results = fut_native.result()
            yara_results = fut_yara.result()

        ml_clf = get_static_malware_classifier()
        feature_vector = ml_clf.extract_feature_vector_from_static_analysis(
            manifest_results=manifest_results,
            code_results=code_results,
            native_results=native_results,
        )
        ml_results = safe_run(
            ml_clf.predict,
            feature_vector,
            default={"prediction": "unknown", "malware_probability": 0.0, "benign_probability": 0.0},
        )

        risk_results = calculate_risk(
            manifest_results,
            code_results,
            resource_results,
            native_results,
            yara_results,
            cert_results,
            ml_results,
        )

        ioc_results = generate_iocs(metadata, code_results, resource_results, cert_results)

        with open(os.path.join(RESULTS_DIR, f"{apk_id}_ioc.json"), "w") as f:
            json.dump(ioc_results, f, indent=4)

        from backend.app.static_analysis.aggregator import generate_ioc_csv
        generate_ioc_csv(ioc_results, os.path.join(RESULTS_DIR, f"{apk_id}_ioc.csv"))

        final_results = {
            "apk_id": apk_id,
            "metadata": metadata,
            "extraction": {"tree": extraction_tree},
            "manifest_analysis": manifest_results,
            "certificate_analysis": cert_results,
            "code_analysis": code_results,
            "codebert_similarity": code_results.get("codebert_similarity", {}) if isinstance(code_results, dict) else {},
            "resource_analysis": resource_results,
            "native_library_analysis": native_results,
            "yara_matches": yara_results,
            "ml_classification": ml_results,
            "static_feature_vector": feature_vector,
            "risk_analysis": risk_results,
            "iocs": ioc_results,
        }

        with open(os.path.join(RESULTS_DIR, f"{apk_id}_report.json"), "w") as f:
            json.dump(final_results, f, indent=4)
        with open(os.path.join(RESULTS_DIR, f"{apk_id}_static.json"), "w") as f:
            json.dump(final_results, f, indent=4)

        return final_results

    except HTTPException:
        raise
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except Exception as err:
        logger.exception(f"Unexpected error in pipeline: {err}")
        raise HTTPException(status_code=500, detail="Internal server error during static analysis.")
    finally:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)


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

