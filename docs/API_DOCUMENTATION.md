# API Documentation

## `POST /api/static-analysis/upload`

**Description:** Main pipeline endpoint for static analysis.
**Content-Type:** `multipart/form-data`

### Request parameters:
- `file`: The `.apk` file to analyze (Max size: 200MB).

### Success Response:
**Code:** `200 OK`
**Content:**
```json
{
  "apk_id": "123e4567-e89b-12d3-a456-426614174000",
  "metadata": {
    "sha256": "...",
    "md5": "...",
    "size": 1500000
  },
  "extraction": {
    "tree": [
      "AndroidManifest.xml",
      "classes.dex",
      "res/",
      "lib/"
    ]
  },
  "manifest": { ... },
  "code_analysis": { ... },
  "resources": { ... },
  "native_libs": { ... },
  "yara_matches": [ ... ],
  "risk_score": {
    "score": 60,
    "level": "High",
    "breakdown": [ ... ]
  }
}
```

### Error Responses:
**Code:** `400 Bad Request`
```json
{
  "detail": "Invalid file format. Only .apk files are allowed."
}
```
**Code:** `413 Payload Too Large`
```json
{
  "detail": "File exceeds the 200MB limit."
}
```
