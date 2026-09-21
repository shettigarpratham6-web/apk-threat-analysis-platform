const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

/**
 * Generic helper for processing fetch response JSON and throwing clean errors.
 */
async function handleResponse(response) {
  if (!response.ok) {
    let errorDetail = `HTTP ${response.status} ${response.statusText}`;
    try {
      const errorJson = await response.json();
      if (errorJson && errorJson.detail) {
        errorDetail = errorJson.detail;
      }
    } catch (_) {
      // JSON parsing fallback
    }
    throw new Error(errorDetail);
  }
  return await response.json();
}

/**
 * Stage 1: Upload APK and execute static analysis pipeline.
 */
export async function uploadAndAnalyzeStatic(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/api/static-analysis/analyze`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}

/**
 * Stage 2: Launch Sandbox Emulator.
 */
export async function startSandbox() {
  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/sandbox/start`, {
    method: "POST",
  });
  return handleResponse(response);
}

/**
 * Stage 3: Install & Run APK in Sandbox.
 */
export async function runApk(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/run`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}

/**
 * Stage 4: Monitor Dynamic Behavior (mitmproxy + Frida).
 */
export async function monitorBehavior(apkId, packageName, duration = 10) {
  const formData = new FormData();
  formData.append("apk_id", apkId);
  if (packageName) {
    formData.append("package_name", packageName);
  }
  formData.append("duration", duration.toString());

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/monitor`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}

/**
 * Stage 5: C2 Detection.
 */
export async function detectC2(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/c2-detect`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}

/**
 * Stage 6: Suspicious Servers Reputation Lookup.
 */
export async function checkServers(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/check-servers`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}

/**
 * Stage 7: Correlation & Unified Risk Score.
 */
export async function correlate(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/correlation/analyze`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}

/**
 * Stage 8: Generate Forensic Report (PDF & HTML).
 */
export async function generateReport(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/report/generate`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}

/**
 * Returns direct URL for HTML report view.
 */
export function getReportViewUrl(apkId) {
  return `${API_BASE_URL}/api/report/${apkId}/view`;
}

/**
 * Returns direct URL for PDF report download.
 */
export function getReportDownloadUrl(apkId) {
  return `${API_BASE_URL}/api/report/${apkId}/download`;
}
