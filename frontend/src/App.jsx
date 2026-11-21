import React, { useEffect, useState } from "react";
import LandingPage from "./pages/LandingPage";
import TestingDashboard from "./pages/TestingDashboard";
import AuthPage from "./pages/AuthPage";
import { getSafeNext, useAuth } from "./auth/AuthContext";

const PROTECTED_PATHS = ["/test", "/analysis", "/dashboard"];
const AUTH_PATHS = ["/login", "/signup"];

export default function App() {
  const { user, loading, logout } = useAuth();
  const [currentPath, setCurrentPath] = useState(() => window.location.pathname || "/");

  useEffect(() => {
    const handlePopState = () => setCurrentPath(window.location.pathname || "/");
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  // `to` may carry a query string (e.g. "/login?next=%2Ftest"); routing only looks at the pathname.
  const navigate = (to, { replace = false } = {}) => {
    window.history[replace ? "replaceState" : "pushState"]({}, "", to);
    setCurrentPath(to.split(/[?#]/)[0] || "/");
    window.scrollTo(0, 0);
  };

  const isProtected = PROTECTED_PATHS.includes(currentPath);
  const isAuthPage = AUTH_PATHS.includes(currentPath);

  // Route guards: logged-out users are sent to /login, logged-in users are kept off /login and /signup.
  useEffect(() => {
    if (loading) return;
    if (isProtected && !user) {
      navigate(`/login?next=${encodeURIComponent(currentPath)}`, { replace: true });
    } else if (isAuthPage && user) {
      navigate(getSafeNext(), { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, user, currentPath]);

  const handleLogout = async () => {
    navigate("/"); // leave the protected page first so the guard doesn't bounce us to /login
    try {
      await logout();
    } catch {
      /* cookie may already be gone; local state is cleared either way */
    }
  };

  // Verifying the cookie, or a redirect is about to happen.
  if (loading || (isProtected && !user) || (isAuthPage && user)) {
    return <div className="auth-splash">VERIFYING SESSION…</div>;
  }

  if (isProtected) {
    return <TestingDashboard onReturnHome={() => navigate("/")} user={user} onLogout={handleLogout} />;
  }

  if (isAuthPage) {
    return <AuthPage mode={currentPath === "/signup" ? "signup" : "login"} navigate={navigate} />;
  }

  return (
    <LandingPage
      user={user}
      onStartTesting={() => navigate("/test")}
      onSignIn={() => navigate("/login")}
    />
  );
}
