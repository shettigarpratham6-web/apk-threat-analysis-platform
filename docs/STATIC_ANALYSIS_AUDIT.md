# Static Analysis Audit Report

## 1. Project Overview
APK Threat Analysis Platform is a malware analysis platform that performs forensic inspection of Android APK files. The current milestone focuses on Static Analysis, where APK contents are extracted and inspected without executing the application.

## 2. Current Architecture & Workflow
The current architecture processes APK files sequentially:
APK Upload -> Validation -> Extraction -> AndroidManifest.xml Parsing -> DEX Inspection -> Resource/Asset Scan -> YARA Signature Matching -> Risk Correlation -> Threat Report

## 3. Working vs. Broken Modules
| Module | File | Status |
|--------|------|--------|
| APK Upload | `routes/static_analysis.py` | Partially Working (Needs hardening) |
| APK Extraction | `apk_loader.py` | Partially Working (Needs secure `apk_extractor.py`) |
| Manifest Analysis | `manifest_check.py` | Partial (Needs intent filter/exported component parsing) |
| Code Scan | `code_analysis.py` | Partial (Needs Jadx integration) |
| Signature Scan | `signature_check.py` | Partial (Needs integration with local `yara_rules/`) |

## 4. Missing Files
- `backend/app/static_analysis/apk_extractor.py`
- `backend/app/static_analysis/resource_analysis.py`
- `backend/app/static_analysis/native_library_analysis.py`
- `backend/app/reporting/report_generator.py`

## 5. Security Issues
- Missing strict MIME validation for uploaded APKs.
- Potential ZIP Slip vulnerability in standard unzipping.
- Lack of cleanup for temporary directories post-extraction.
- No robust error handling (structured JSON formats).

## 6. TODO Checklist
- [x] Environment setup (Dependencies, JADX, Apktool)
- [ ] Implement `apk_extractor.py` with security measures
- [ ] Enhance manifest and code analysis
- [ ] Implement resource and native library analysis
- [ ] Develop the forensic report generator
- [ ] Update frontend UI to show static analysis stages
