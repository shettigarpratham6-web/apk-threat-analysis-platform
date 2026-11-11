import React from "react";
import "./LandingPage.css";

export default function LandingPage({ onStartTesting }) {
  return (
    <div className="landing-page">
      {/* FULL PAGE ANIMATED BACKGROUND */}
      <div className="landing-background" aria-hidden="true">
        <div className="ambient-glow"></div>

        <div className="digital-globe">
          <div className="globe-meridian meridian-one"></div>
          <div className="globe-meridian meridian-two"></div>
          <div className="globe-meridian meridian-three"></div>
          <div className="globe-equator"></div>
          <div className="globe-equator equator-two"></div>
        </div>

        <div className="orbit orbit-one"></div>
        <div className="orbit orbit-two"></div>
        <div className="orbit orbit-three"></div>

        {/* FULL PAGE ASTEROID FIELD */}
        <div className="asteroid-field">
          {[
            { size: 40, top: 8, duration: 17, delay: -4 },
            { size: 24, top: 15, duration: 11, delay: -7 },
            { size: 55, top: 25, duration: 21, delay: -12 },
            { size: 30, top: 35, duration: 13, delay: -3 },
            { size: 45, top: 48, duration: 19, delay: -15 },
            { size: 20, top: 58, duration: 10, delay: -6 },
            { size: 35, top: 68, duration: 15, delay: -9 },
            { size: 52, top: 78, duration: 22, delay: -18 },
            { size: 26, top: 88, duration: 12, delay: -5 },
            { size: 18, top: 95, duration: 9, delay: -2 }
          ].map((item, index) => (
            <div
              className="asteroid-track"
              key={index}
              style={{
                "--size": `${item.size}px`,
                "--top": `${item.top}%`,
                "--duration": `${item.duration}s`,
                "--delay": `${item.delay}s`
              }}
            >
              <div className={`asteroid-body asteroid-shape-${index % 4}`}>
                <span className="asteroid-crater crater-one"></span>
                <span className="asteroid-crater crater-two"></span>
              </div>
            </div>
          ))}
        </div>

        {/* FLOATING PARTICLES */}
        <div className="floating-particles">
          {Array.from({ length: 35 }, (_, i) => (
            <span
              key={i}
              className="particle"
              style={{
                "--i": i,
                "--delay": `${i * -0.6}s`
              }}
            />
          ))}
        </div>
      </div>

      {/* ALL EXISTING PAGE CONTENT */}
      <div className="landing-content">
        <nav className="cyber-nav">
          <a href="#home" className="cyber-brand">
            <span className="brand-symbol">✳</span>
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
            onClick={onStartTesting}
          >
            SIGN IN
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
              Analyze Android applications using advanced
              static and dynamic analysis, runtime monitoring,
              threat intelligence and evidence-based AI reporting.
            </p>

            <div className="hero-actions">
              <button
                className="primary-action"
                onClick={onStartTesting}
              >
                SIGN IN TO TEST APK
              </button>

              <a
                href="#features"
                className="secondary-action"
              >
                EXPLORE FEATURES
              </a>
            </div>
          </div>

          <div className="hero-art">
            <div className="cyber-laptop">
              <div className="laptop-screen">
                <div className="screen-content">
                  <div className="screen-lock">🔒</div>
                  <h2>SYSTEM SECURED</h2>
                  <div className="screen-status">
                    <span className="status-dot"></span>
                    THREAT MONITORING ACTIVE
                  </div>
                </div>
              </div>

              <div className="laptop-hinge"></div>

              <div className="laptop-base">
                <div className="keyboard-area">
                  <div className="keyboard-row">
                    {["ESC","F1","F2","F3","F4","F5","F6","F7","F8","F9","F10","F11","F12","DEL"].map(key => (
                      <span className="key function-key" key={key}>{key}</span>
                    ))}
                  </div>

                  <div className="keyboard-row">
                    {["~","1","2","3","4","5","6","7","8","9","0","-","=","BACK"].map(key => (
                      <span className="key" key={key}>{key}</span>
                    ))}
                  </div>

                  <div className="keyboard-row">
                    {["TAB","Q","W","E","R","T","Y","U","I","O","P","[","]","\\"].map(key => (
                      <span className="key" key={key}>{key}</span>
                    ))}
                  </div>

                  <div className="keyboard-row">
                    {["CAPS","A","S","D","F","G","H","J","K","L",";","ENTER"].map(key => (
                      <span className="key" key={key}>{key}</span>
                    ))}
                  </div>

                  <div className="keyboard-row">
                    {["SHIFT","Z","X","C","V","B","N","M",",",".","/","SHIFT"].map((key, i) => (
                      <span className="key" key={`${key}-${i}`}>{key}</span>
                    ))}
                  </div>

                  <div className="keyboard-row bottom-row">
                    <span className="key">CTRL</span>
                    <span className="key">FN</span>
                    <span className="key">ALT</span>
                    <span className="key spacebar"></span>
                    <span className="key">ALT</span>
                    <span className="key">CTRL</span>
                  </div>
                </div>

                <div className="trackpad"></div>
              </div>
            </div>
          </div>
        </section>

        <section className="features-section" id="features">
          <span className="eyebrow">OUR CAPABILITIES</span>

          <h2>
            ADVANCED <span>THREAT DETECTION</span>
          </h2>

          <div className="feature-grid">
            {[
              ["01", "STATIC ANALYSIS",
                "APK metadata, permissions, manifest inspection, DEX analysis and suspicious API detection."],
              ["02", "DYNAMIC ANALYSIS",
                "Real-time application execution, emulator monitoring and runtime behavior analysis."],
              ["03", "THREAT INTELLIGENCE",
                "Suspicious domains, IP reputation, malware signatures and threat correlation."],
              ["04", "AI-POWERED ANALYSIS",
                "Evidence-based explanations and detailed malware analysis summaries."],
              ["05", "FORENSIC REPORTING",
                "Detailed findings, supporting evidence and professional PDF reports."],
              ["06", "SECURITY MONITORING",
                "Runtime indicators, suspicious activities and application behavior monitoring."]
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
          <span className="eyebrow">SIMPLE WORKFLOW</span>

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
              <p>Perform static and dynamic malware analysis.</p>
            </div>

            <div>
              <span>03</span>
              <h3>VIEW RESULTS</h3>
              <p>Review threats, supporting evidence and reports.</p>
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

          <p>
            Advanced Android application security and malware analysis.
          </p>

          <span>
            ANDROID SECURITY • STATIC ANALYSIS • DYNAMIC ANALYSIS
          </span>
        </footer>
      </div>
    </div>
  );
}
