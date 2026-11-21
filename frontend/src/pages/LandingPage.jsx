import React from "react";
import useVantaGlobe from "../hooks/useVantaGlobe";
import "./LandingPage.css";

export default function LandingPage({ user, onStartTesting, onSignIn }) {
  const bgRef = useVantaGlobe();

  return (
    <div className="landing-page">
      <div className="landing-background" ref={bgRef} aria-hidden="true" />
      <div className="landing-content">
        <nav className="cyber-nav">
          <a href="#home" className="cyber-brand">
            APK THREAT ANALYSIS
          </a>

          <div className="cyber-links">
            <a href="#home">HOME</a>
            <a href="#about">ABOUT</a>
            <a href="#features">FEATURES</a>
            <a href="#contact">CONTACT</a>
          </div>

          <button
            className="nav-signin"
            onClick={user ? onStartTesting : onSignIn}
          >
            {user ? "OPEN ANALYZER" : "SIGN IN"}
          </button>
        </nav>

        <section className="cyber-hero" id="home">
          <div className="hero-copy">
            <span className="eyebrow">
              ANDROID SECURITY PLATFORM
            </span>

            <h1>
              ANDROID
              <br />
              <span>MALWARE</span>
              <br />
              ANALYSIS
            </h1>

            <h3>DETECT. ANALYZE. PROTECT.</h3>

            <p>
              Upload an APK to get static analysis, sandboxed runtime behaviour, extracted indicators, and a downloadable report.
            </p>

            <div className="hero-actions">
              <button
                className="primary-action"
                onClick={onStartTesting}
              >
                UPLOAD AN APK
              </button>

              <a
                href="#features"
                className="secondary-action"
              >
                EXPLORE FEATURES
              </a>
            </div>
          </div>
        </section>

        <section className="features-section" id="features">
          <h2>Features</h2>

          <div className="feature-grid">
            {[
              ["01", "STATIC ANALYSIS",
                "Extracts metadata, permissions, certificates, DEX bytecode, and suspicious API invocations."],
              ["02", "DYNAMIC SANDBOX",
                "Executes the application in an Android emulator with runtime activity and network monitoring."],
              ["03", "C2 DETECTION",
                "Detects periodic beaconing patterns, algorithmically generated domains, and suspicious network ports."],
              ["04", "MACHINE LEARNING",
                "Evaluates 215 static features against a Random Forest model to predict malware probability."],
              ["05", "SERVER REPUTATION",
                "Queries VirusTotal and AbuseIPDB to score observed external IP addresses and domains."],
              ["06", "FORENSIC REPORTING",
                "Compiles findings, Indicators of Compromise, and evidence into downloadable PDF and HTML reports."]
            ].map(([number, title, description]) => (
              <article className="feature-card" key={number}>
                <span className="feature-number">{number}</span>
                <h3>{title}</h3>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="workflow-section" id="about">
          <span className="eyebrow">WORKFLOW</span>

          <h2>HOW IT <span>WORKS</span></h2>

          <div className="workflow-grid">
            <div>
              <span>01</span>
              <h3>UPLOAD APK</h3>
              <p>Upload the Android application for inspection.</p>
            </div>

            <div>
              <span>02</span>
              <h3>ANALYZE</h3>
              <p>Execute static inspection and dynamic sandbox analysis.</p>
            </div>

            <div>
              <span>03</span>
              <h3>VIEW RESULTS</h3>
              <p>Review threat scores, indicators of compromise, and forensic reports.</p>
            </div>
          </div>

          <button
            className="primary-action"
            onClick={onStartTesting}
          >
            START ANALYSIS
          </button>
        </section>

        <footer className="cyber-footer" id="contact">
          <strong>APK THREAT ANALYSIS</strong>
          <span>
            ANDROID SECURITY | STATIC ANALYSIS | DYNAMIC ANALYSIS
          </span>
        </footer>
      </div>
    </div>
  );
}
