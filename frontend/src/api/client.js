const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

function getHeaders(customHeaders = {}) {
  return { ...customHeaders };
}

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

export async function checkSystemHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);
  return handleResponse(response);
}

export async function uploadApk(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/api/static-analysis/upload`, {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });
  return handleResponse(response);
}

export async function uploadAndAnalyzeStatic(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/api/static-analysis/analyze`, {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });
  return handleResponse(response);
}

export async function startSandbox() {
  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/sandbox/start`, {
    method: "POST",
    headers: getHeaders(),
  });
  return handleResponse(response);
}

export async function stopSandbox() {
  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/sandbox/stop`, {
    method: "POST",
    headers: getHeaders(),
  });
  return handleResponse(response);
}

export async function runApk(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/run`, {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });
  return handleResponse(response);
}

export async function monitorBehavior(apkId, packageName, duration = 15) {
  const formData = new FormData();
  formData.append("apk_id", apkId);
  if (packageName) {
    formData.append("package_name", packageName);
  }
  formData.append("duration", duration.toString());

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/monitor`, {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });
  return handleResponse(response);
}

export async function detectC2(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/c2-detect`, {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });
  return handleResponse(response);
}

export async function checkServers(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/check-servers`, {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });
  return handleResponse(response);
}

export async function correlate(apkId) {
  const formData = new FormData();
  formData.append("apk_id", apkId);

  const response = await fetch(`${API_BASE_URL}/api/correlation/analyze`, {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });
  return handleResponse(response);
}

export async function generateReport(apkId) {
  const response = await fetch(`${API_BASE_URL}/api/report/generate/${apkId}`, {
    method: "POST",
    headers: getHeaders(),
  });
  return handleResponse(response);
}

export function getReportViewUrl(apkId) {
  return `${API_BASE_URL}/api/report/view/${apkId}`;
}

export function getReportDownloadUrl(apkId) {
  return `${API_BASE_URL}/api/report/download/${apkId}?format=pdf`;
}

export function getReportJsonDownloadUrl(apkId) {
  return `${API_BASE_URL}/api/report/download/${apkId}?format=json`;
}

export function getReportIocJsonUrl(apkId) {
  return `${API_BASE_URL}/api/report/download/${apkId}?format=ioc`;
}

export function getReportIocCsvUrl(apkId) {
  return `${API_BASE_URL}/api/report/download/${apkId}?format=csv`;
}

export function getDeviceScreenUrl() {
  return `${API_BASE_URL}/api/dynamic-analysis/screen/current?_t=${Date.now()}`;
}

export async function getDeviceInfo() {
  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/screen/info`, {
    headers: getHeaders(),
  });
  return handleResponse(response);
}

export async function sendDeviceTouch(payload) {
  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/screen/touch`, {
    method: "POST",
    headers: getHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
  });
  return handleResponse(response);
}

export async function wakeDevice() {
  const response = await fetch(`${API_BASE_URL}/api/dynamic-analysis/sandbox/wake`, {
    method: "POST",
    headers: getHeaders(),
  });
  return handleResponse(response);
}
