import React, { useState, useEffect } from "react";
import LandingPage from "./pages/LandingPage";
import TestingDashboard from "./pages/TestingDashboard";

export default function App() {
  const [currentPath, setCurrentPath] = useState(() => {
    return window.location.pathname || "/";
  });

  useEffect(() => {
    const handlePopState = () => {
      setCurrentPath(window.location.pathname || "/");
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = (to) => {
    window.history.pushState({}, "", to);
    setCurrentPath(to);
    window.scrollTo(0, 0);
  };

  // If URL path is /test, /analysis, or /dashboard, render the Testing Dashboard
  if (
    currentPath === "/test" ||
    currentPath === "/analysis" ||
    currentPath === "/dashboard"
  ) {
    return <TestingDashboard onReturnHome={() => navigate("/")} />;
  }

  // Default initial entry is the Cybersecurity Landing Page
  return (
    <LandingPage
      onStartTesting={() => navigate("/test")}
    />
  );
}
