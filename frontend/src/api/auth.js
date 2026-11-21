const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

function formatDetail(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // FastAPI/Pydantic validation errors: [{ msg: "Value error, ..." }, ...]
    return detail
      .map((d) => String(d.msg || "").replace(/^Value error,\s*/i, ""))
      .filter(Boolean)
      .join(" ");
  }
  return "";
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      credentials: "include", // send/receive the httpOnly session cookie
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch {
    throw new Error("Cannot reach the server. Check that the backend is running on port 8000.");
  }

  if (response.ok) return response.json();

  let message = `Request failed (HTTP ${response.status}).`;
  try {
    const body = await response.json();
    message = formatDetail(body.detail) || message;
  } catch {
    /* non-JSON error body */
  }
  const error = new Error(message);
  error.status = response.status;
  throw error;
}

/** Returns the current user, or null when there is no valid session. */
export async function fetchMe() {
  try {
    return await request("/api/auth/me");
  } catch (error) {
    if (error.status === 401) return null;
    throw error;
  }
}

export const login = (email, password) =>
  request("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });

export const signup = ({ fullName, email, password }) =>
  request("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify({ full_name: fullName, email, password }),
  });

export const logout = () => request("/api/auth/logout", { method: "POST" });
