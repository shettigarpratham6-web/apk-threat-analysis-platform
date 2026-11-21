import React, { useMemo, useRef, useState } from "react";
import useVantaGlobe from "../hooks/useVantaGlobe";
import { useAuth } from "../auth/AuthContext";
import "./LandingPage.css"; // reuse the landing page's nav, hero, button and footer styles verbatim
import "./AuthPage.css";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const STRENGTH_LABELS = ["TOO WEAK", "WEAK", "FAIR", "GOOD", "STRONG"];

function scorePassword(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  return score; // 0..4
}

// Keep these rules identical to the backend (SignupIn / LoginIn in backend/app/routes/auth.py).
function validate(isSignup, v) {
  const errors = {};
  if (isSignup && v.fullName.trim().length < 2) errors.fullName = "Enter your full name.";
  if (!EMAIL_RE.test(v.email.trim())) errors.email = "Enter a valid email address.";
  if (isSignup) {
    if (v.password.length < 8) errors.password = "Use at least 8 characters.";
    else if (new TextEncoder().encode(v.password).length > 72) errors.password = "Use at most 72 characters.";
    else if (!/[A-Za-z]/.test(v.password) || !/\d/.test(v.password))
      errors.password = "Include at least one letter and one number.";
    if (v.confirm !== v.password) errors.confirm = "Passwords do not match.";
    if (!v.ack) errors.ack = "You must accept the authorized-use terms.";
  } else if (!v.password) {
    errors.password = "Enter your password.";
  }
  return errors;
}

function AuthForm({ isSignup, go }) {
  const { login, signup } = useAuth();
  const formRef = useRef(null);
  const [values, setValues] = useState({ fullName: "", email: "", password: "", confirm: "", ack: false });
  const [touched, setTouched] = useState({});
  const [attempted, setAttempted] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [serverError, setServerError] = useState("");

  const errors = useMemo(() => validate(isSignup, values), [isSignup, values]);
  const show = (name) => Boolean(errors[name]) && (attempted || touched[name]);
  const strength = scorePassword(values.password);

  const bind = (name) => ({
    id: `f-${name}`,
    name,
    value: values[name],
    onChange: (e) => setValues((v) => ({ ...v, [name]: e.target.value })),
    onBlur: () => setTouched((t) => ({ ...t, [name]: true })),
    "aria-invalid": show(name) ? "true" : "false",
    "aria-describedby": show(name) ? `e-${name}` : undefined,
  });

  const fieldError = (name) =>
    show(name) ? (
      <span className="auth-error" id={`e-${name}`} role="alert">
        {errors[name]}
      </span>
    ) : null;

  const onSubmit = async (e) => {
    e.preventDefault();
    setAttempted(true);
    setServerError("");
    if (Object.keys(errors).length > 0) {
      requestAnimationFrame(() => formRef.current?.querySelector('[aria-invalid="true"]')?.focus());
      return;
    }
    setSubmitting(true);
    try {
      if (isSignup) {
        await signup({ fullName: values.fullName.trim(), email: values.email.trim(), password: values.password });
      } else {
        await login(values.email.trim(), values.password);
      }
      // Success: <App> sees the new user and redirects to ?next= (or /test).
    } catch (err) {
      setServerError(err.message || "Something went wrong. Please try again.");
      setSubmitting(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={onSubmit} noValidate ref={formRef}>
      <span className="eyebrow">{isSignup ? "// CREATE ACCOUNT" : "// SIGN IN"}</span>

      {serverError && (
        <div className="auth-banner" role="alert">
          {serverError}
        </div>
      )}

      {isSignup && (
        <div className="auth-field">
          <label htmlFor="f-fullName">FULL NAME</label>
          <input {...bind("fullName")} type="text" autoComplete="name" placeholder="Ada Lovelace" autoFocus />
          {fieldError("fullName")}
        </div>
      )}

      <div className="auth-field">
        <label htmlFor="f-email">EMAIL</label>
        <input
          {...bind("email")}
          type="email"
          autoComplete="username"
          placeholder="analyst@company.com"
          autoFocus={!isSignup}
        />
        {fieldError("email")}
      </div>

      <div className="auth-field">
        <label htmlFor="f-password">PASSWORD</label>
        <div className="auth-pw">
          <input
            {...bind("password")}
            type={showPw ? "text" : "password"}
            autoComplete={isSignup ? "new-password" : "current-password"}
            placeholder="••••••••"
          />
          <button
            type="button"
            className="auth-pw-toggle"
            onClick={() => setShowPw((s) => !s)}
            aria-pressed={showPw}
            aria-label={showPw ? "Hide password" : "Show password"}
          >
            {showPw ? "HIDE" : "SHOW"}
          </button>
        </div>
        {fieldError("password")}

        {isSignup && values.password && (
          <div className="auth-meter" aria-live="polite">
            <div className="auth-meter-bars" data-level={strength}>
              <i />
              <i />
              <i />
              <i />
            </div>
            <span>{STRENGTH_LABELS[strength]}</span>
          </div>
        )}
      </div>

      {isSignup && (
        <>
          <div className="auth-field">
            <label htmlFor="f-confirm">CONFIRM PASSWORD</label>
            <input
              {...bind("confirm")}
              type={showPw ? "text" : "password"}
              autoComplete="new-password"
              placeholder="••••••••"
            />
            {fieldError("confirm")}
          </div>

          <div className="auth-field">
            <label className="auth-check" htmlFor="f-ack">
              <input
                id="f-ack"
                type="checkbox"
                checked={values.ack}
                onChange={(e) => setValues((v) => ({ ...v, ack: e.target.checked }))}
                aria-invalid={show("ack") ? "true" : "false"}
                aria-describedby={show("ack") ? "e-ack" : undefined}
              />
              <span>I will only analyze samples I am authorized to handle, inside an isolated sandbox.</span>
            </label>
            {fieldError("ack")}
          </div>
        </>
      )}

      <button className="primary-action auth-submit" type="submit" disabled={submitting}>
        {submitting ? "AUTHENTICATING…" : isSignup ? "CREATE ACCOUNT" : "SIGN IN"}
      </button>

      <p className="auth-switch">
        {isSignup ? "ALREADY HAVE AN ACCOUNT?" : "NEW TO THE PLATFORM?"}{" "}
        <a href={isSignup ? "/login" : "/signup"} onClick={go(isSignup ? "/login" : "/signup")}>
          {isSignup ? "SIGN IN" : "CREATE ACCOUNT"}
        </a>
      </p>
    </form>
  );
}

export default function AuthPage({ mode, navigate }) {
  const bgRef = useVantaGlobe();
  const isSignup = mode === "signup";

  // SPA navigation that preserves ?next=
  const go = (to) => (e) => {
    e.preventDefault();
    navigate(`${to}${window.location.search}`);
  };

  return (
    <div className="landing-page auth-page">
      <div className="landing-background" ref={bgRef} aria-hidden="true" />

      <div className="landing-content auth-layout">
        <nav className="cyber-nav">
          <a href="/" className="cyber-brand">
            APK THREAT ANALYSIS
          </a>

          <div className="cyber-links">
            <a href="/#home">HOME</a>
            <a href="/#about">ABOUT</a>
            <a href="/#features">FEATURES</a>
            <a href="/#contact">CONTACT</a>
          </div>

          <button className="nav-signin" onClick={go(isSignup ? "/login" : "/signup")}>
            {isSignup ? "SIGN IN" : "CREATE ACCOUNT"}
          </button>
        </nav>

        <main className="auth-main">
          <div className="hero-copy auth-copy">
            <span className="eyebrow">ANDROID SECURITY PLATFORM</span>

            <h1>
              {isSignup ? (
                <>
                  CREATE
                  <br />
                  <span>ANALYST</span>
                  <br />
                  ACCOUNT
                </>
              ) : (
                <>
                  ANALYST
                  <br />
                  <span>ACCESS</span>
                </>
              )}
            </h1>

            <h3>DETECT. ANALYZE. PROTECT.</h3>

            <p>
              {isSignup
                ? "Create an account to submit APKs for static analysis, dynamic sandboxing, and C2 detection."
                : "Sign in to upload APKs, run the sandbox, and download forensic reports."}
            </p>
          </div>

          <section className="auth-card" aria-label={isSignup ? "Create account" : "Sign in"}>
            <AuthForm key={mode} isSignup={isSignup} go={go} />
          </section>
        </main>

        <footer className="cyber-footer" id="contact">
          <strong>APK THREAT ANALYSIS</strong>
          <span>ANDROID SECURITY | STATIC ANALYSIS | DYNAMIC ANALYSIS</span>
        </footer>
      </div>
    </div>
  );
}
