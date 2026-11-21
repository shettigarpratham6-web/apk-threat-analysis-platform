import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import * as authApi from "../api/auth";

const AuthContext = createContext(null);

/** Reads ?next=/some/path, accepting only same-site paths (blocks open redirects like //evil.com). */
export function getSafeNext(fallback = "/test") {
  const next = new URLSearchParams(window.location.search).get("next");
  const isLocalPath = next && /^\/(?![/\\])/.test(next);
  const isAuthPath = next && /^\/(login|signup)(\/|\?|#|$)/.test(next);
  return isLocalPath && !isAuthPath ? next : fallback;
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Restore the session (cookie) on first load.
  useEffect(() => {
    let alive = true;
    authApi
      .fetchMe()
      .then((u) => alive && setUser(u))
      .catch(() => alive && setUser(null))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, []);

  // client.js dispatches this when any analysis call returns 401 (session expired mid-use).
  useEffect(() => {
    const onExpired = () => setUser(null);
    window.addEventListener("auth:expired", onExpired);
    return () => window.removeEventListener("auth:expired", onExpired);
  }, []);

  const login = useCallback(async (email, password) => {
    const u = await authApi.login(email, password);
    setUser(u);
    return u;
  }, []);

  const signup = useCallback(async (details) => {
    const u = await authApi.signup(details);
    setUser(u);
    return u;
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const value = useMemo(
    () => ({ user, loading, login, signup, logout }),
    [user, loading, login, signup, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
