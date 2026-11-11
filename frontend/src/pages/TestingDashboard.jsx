import React, { useState, useEffect } from "react";
import "../App.css";

import UploadPanel from "../components/UploadPanel";
import PipelineStepper from "../components/PipelineStepper";
import ResultsPanel from "../components/ResultsPanel";
import RiskBanner from "../components/RiskBanner";
import ReportViewer from "../components/ReportViewer";
import LiveVirtualDevice from "../components/LiveVirtualDevice";

import {
  uploadAndAnalyzeStatic,
  uploadApk,
  startSandbox,
  runApk,
  monitorBehavior,
  detectC2,
  checkServers,
  correlate,
  generateReport,
  checkSystemHealth
} from "../api/client";

const STATIC_STAGES = [
  { id: "upload", title: "1. Upload APK", subtitle: "Submit file to backend", status: "pending" },
  { id: "extract", title: "2. Extract APK", subtitle: "Secure unzip & tree generation", status: "pending" },
  { id: "manifest", title: "3. Manifest Scan", subtitle: "Permissions & Components", status: "pending" },
  { id: "permissions", title: "4. Permission Analysis", subtitle: "Risk categorization", status: "pending" },
  { id: "code", title: "5. DEX Code Scan", subtitle: "URLs, IPs & Suspicious APIs", status: "pending" },
  { id: "resources", title: "6. Resource Scan", subtitle: "Secrets & API Keys", status: "pending" },
  { id: "native", title: "7. Native Library Scan", subtitle: "ABI & Suspicious SOs", status: "pending" },
  { id: "yara", title: "8. YARA Scan", subtitle: "Signature matching", status: "pending" },
  { id: "risk", title: "9. Risk Correlation", subtitle: "Threat scoring & ML", status: "pending" },
  { id: "report", title: "10. Threat Report", subtitle: "Forensic documentation", status: "pending" },
];

const DYNAMIC_STAGES = [
  { id: "dyn_prep", title: "1. Sandbox Environment", subtitle: "Verify & Start Android Emulator", status: "pending" },
  { id: "dyn_deploy", title: "2. Deploy Target APK", subtitle: "Install APK & launch in sandbox", status: "pending" },
  { id: "dyn_monitor", title: "3. Behavior Telemetry", subtitle: "Frida hooks & mitmproxy capture", status: "pending" },
  { id: "dyn_c2", title: "4. C2 Detection", subtitle: "Beaconing & network pattern audit", status: "pending" },
  { id: "dyn_reputation", title: "5. Threat Intelligence", subtitle: "AbuseIPDB & VirusTotal scoring", status: "pending" },
  { id: "dyn_report", title: "6. Unified Forensic Report", subtitle: "Risk correlation & artifacts", status: "pending" },
];

export default function TestingDashboard({ onReturnHome }) {
  const [activeTab, setActiveTab] = useState("static"); // "static" or "dynamic"
  const [staticStages, setStaticStages] = useState(STATIC_STAGES);
  const [dynamicStages, setDynamicStages] = useState(DYNAMIC_STAGES);
  const [currentStageIndex, setCurrentStageIndex] = useState(0);

  const [apkId, setApkId] = useState(null);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [stageResults, setStageResults] = useState({});
  const [dynamicResults, setDynamicResults] = useState({});
  const [globalError, setGlobalError] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [backendOnline, setBackendOnline] = useState(true);
  const [dynamicDuration, setDynamicDuration] = useState(15);

  useEffect(() => {
    checkSystemHealth()
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  const handleHomeClick = () => {
    if (onReturnHome) {
      onReturnHome();
    } else {
      window.history.pushState({}, "", "/");
      window.dispatchEvent(new PopStateEvent("popstate"));
    }
  };

  const updateStageStatus = (isDynamic, index, status) => {
    if (isDynamic) {
      setDynamicStages((prev) => {
        const copy = [...prev];
        if (copy[index]) copy[index] = { ...copy[index], status };
        return copy;
      });
    } else {
      setStaticStages((prev) => {
        const copy = [...prev];
        if (copy[index]) copy[index] = { ...copy[index], status };
        return copy;
      });
    }
  };

  const handleStaticUploadAndAnalyze = async (file) => {
    if (!file) {
      setGlobalError("Please select a valid .apk file first.");
      return;
    }
    setUploadedFile(file);
    setGlobalError(null);
    setIsRunning(true);
    setStaticStages(STATIC_STAGES.map(s => ({ ...s, status: "pending" })));
    setStageResults({});
    setCurrentStageIndex(0);
    updateStageStatus(false, 0, "running");

    let fakeIdx = 1;
    const fakeInterval = setInterval(() => {
      if (fakeIdx < 7) {
        updateStageStatus(false, fakeIdx - 1, "completed");
        updateStageStatus(false, fakeIdx, "running");
        setCurrentStageIndex(fakeIdx);
        fakeIdx++;
      }
    }, 2500);

    try {
      const data = await uploadAndAnalyzeStatic(file);
      clearInterval(fakeInterval);
      setApkId(data.apk_id);

      const mappedResults = {
        0: { metadata: data.metadata },
        1: { extraction: data.extraction },
        2: { manifest: data.manifest_analysis },
        3: { permissions: data.manifest_analysis?.permissions },
        4: {
          code_analysis: data.code_analysis,
          codebert_similarity: data.codebert_similarity || data.code_analysis?.codebert_similarity
        },
        5: { resource_analysis: data.resource_analysis },
        6: { native_library_analysis: data.native_library_analysis },
        7: { yara_matches: data.yara_matches },
        8: {
          risk_analysis: data.risk_analysis,
          certificate_analysis: data.certificate_analysis,
          iocs: data.iocs,
          ml_classification: data.ml_classification,
          codebert_similarity: data.codebert_similarity || data.code_analysis?.codebert_similarity
        },
        9: { report: true, apkId: data.apk_id }
      };

      setStageResults(mappedResults);

      const delay = (ms) => new Promise(res => setTimeout(res, ms));
      for (let i = fakeIdx - 1; i < STATIC_STAGES.length; i++) {
        setCurrentStageIndex(i);
        updateStageStatus(false, i, "running");
        await delay(400);
        updateStageStatus(false, i, "completed");
      }
      setCurrentStageIndex(9);
    } catch (err) {
      clearInterval(fakeInterval);
      setGlobalError(`Static Analysis failed: ${err.message}`);
      updateStageStatus(false, Math.max(0, fakeIdx - 1), "error");
    } finally {
      setIsRunning(false);
    }
  };

  const handleDynamicRun = async (selectedApkFile) => {
    const fileToUse = selectedApkFile || uploadedFile;
    if (!fileToUse && !apkId) {
      setGlobalError("Please upload an APK file or run Static Analysis first.");
      return;
    }

    setGlobalError(null);
    setIsRunning(true);
    setDynamicStages(DYNAMIC_STAGES.map(s => ({ ...s, status: "pending" })));
    setDynamicResults({});
    setCurrentStageIndex(0);

    try {
      let currentApkId = apkId;

      // Stage 1: Sandbox Environment Setup
      updateStageStatus(true, 0, "running");
      setCurrentStageIndex(0);
      const sandboxInfo = await startSandbox();
      setDynamicResults(prev => ({ ...prev, 0: sandboxInfo }));
      updateStageStatus(true, 0, "completed");

      // Ensure APK is uploaded if not done already
      if (!currentApkId && fileToUse) {
        const uploadRes = await uploadApk(fileToUse);
        currentApkId = uploadRes.apk_id;
        setApkId(currentApkId);
      }

      // Stage 2: Deploy APK to Sandbox
      updateStageStatus(true, 1, "running");
      setCurrentStageIndex(1);
      const deployRes = await runApk(currentApkId);
      const packageName = deployRes.package_name;
      setDynamicResults(prev => ({ ...prev, 1: { ...deployRes, apk_id: currentApkId } }));
      updateStageStatus(true, 1, "completed");

      // Stage 3: Dynamic Behavior Telemetry (mitmproxy + Frida)
      updateStageStatus(true, 2, "running");
      setCurrentStageIndex(2);
      const monitorRes = await monitorBehavior(currentApkId, packageName, dynamicDuration);
      setDynamicResults(prev => ({ ...prev, 2: monitorRes }));
      updateStageStatus(true, 2, "completed");

      // Stage 4: Command & Control (C2) Detection
      updateStageStatus(true, 3, "running");
      setCurrentStageIndex(3);
      const c2Res = await detectC2(currentApkId);
      setDynamicResults(prev => ({ ...prev, 3: c2Res }));
      updateStageStatus(true, 3, "completed");

      // Stage 5: Threat Intelligence Lookup
      updateStageStatus(true, 4, "running");
      setCurrentStageIndex(4);
      const repRes = await checkServers(currentApkId);
      setDynamicResults(prev => ({ ...prev, 4: repRes }));
      updateStageStatus(true, 4, "completed");

      // Stage 6: Unified Risk Correlation & Forensics
      updateStageStatus(true, 5, "running");
      setCurrentStageIndex(5);
      const corrRes = await correlate(currentApkId);
      await generateReport(currentApkId);
      setDynamicResults(prev => ({ ...prev, 5: { ...corrRes, apk_id: currentApkId } }));
      updateStageStatus(true, 5, "completed");

    } catch (err) {
      setGlobalError(`Dynamic Analysis failed: ${err.message}`);
      updateStageStatus(true, currentStageIndex, "error");
    } finally {
      setIsRunning(false);
    }
  };

  const isDynamic = activeTab === "dynamic";
  const stages = isDynamic ? dynamicStages : staticStages;
  const currentResults = isDynamic ? dynamicResults[currentStageIndex] : stageResults[currentStageIndex];

  return (
    <div className="app-container">
      {/* Cybersecurity Top Header */}
      <header className="header">
        <div
          className="header-brand"
          style={{ cursor: "pointer" }}
          onClick={handleHomeClick}
          title="Return to Landing Page"
        >
          <span className="brand-icon">✳</span>
          <div>
            <h1 className="brand-title">
              APK THREAT <span>ANALYSIS</span>
            </h1>
            <p className="brand-subtitle">
              ANDROID SECURITY • STATIC DECOMPILATION & DYNAMIC SANDBOX
            </p>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
          <button
            className="cyber-back-btn"
            onClick={handleHomeClick}
          >
            ← HOME
          </button>

          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="btn btn-outline btn-sm"
          >
            API DOCS
          </a>

          <div className="header-status">
            <span
              className="status-dot"
              style={{ backgroundColor: backendOnline ? "var(--neon-green)" : "var(--danger-red)" }}
            ></span>
            <span>{backendOnline ? "BACKEND ONLINE (8000)" : "BACKEND OFFLINE"}</span>
          </div>
        </div>
      </header>

      {/* Mode Navigation Bar */}
      <div className="mode-nav-bar">
        <button
          onClick={() => { setActiveTab("static"); setCurrentStageIndex(0); }}
          className={`nav-tab-btn ${!isDynamic ? "active" : ""}`}
        >
          🔍 STATIC ENGINE (10 STAGES)
        </button>

        <button
          onClick={() => { setActiveTab("dynamic"); setCurrentStageIndex(0); }}
          className={`nav-tab-btn ${isDynamic ? "active" : ""}`}
        >
          🧪 DYNAMIC SANDBOX & C2 (6 STAGES)
        </button>

        {apkId && (
          <span style={{ marginLeft: "auto", fontSize: "11px", color: "var(--neon-green)", fontFamily: "var(--font-mono)", letterSpacing: "1px" }}>
            SESSION: <strong>{apkId.slice(0, 16)}...</strong>
          </span>
        )}
      </div>

      <main className="main-content">
        {globalError && <div className="error-banner">{globalError}</div>}

        <div className="dashboard-grid">
          <div className="sidebar-col" style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {!isDynamic ? (
              <UploadPanel
                onUpload={handleStaticUploadAndAnalyze}
                onDynamicUpload={(file) => {
                  setActiveTab("dynamic");
                  handleDynamicRun(file);
                }}
                isRunning={isRunning}
              />
            ) : (
              <div className="card upload-card">
                <div className="card-header">
                  <h2 className="card-title">Dynamic Sandbox Execution</h2>
                  <span className="card-badge">EMULATOR LAB</span>
                </div>
                <p className="card-desc">
                  Run target APK inside isolated Android AVD with Frida instrumentation and mitmproxy traffic interception.
                </p>

                <div style={{ marginTop: "12px", marginBottom: "16px" }}>
                  <label style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-muted)", display: "block", marginBottom: "8px", textTransform: "uppercase" }}>
                    Select APK File (Auto-boots fake phone):
                  </label>
                  <input
                    type="file"
                    accept=".apk"
                    disabled={isRunning}
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        const file = e.target.files[0];
                        setUploadedFile(file);
                        handleDynamicRun(file);
                      }
                    }}
                    className="file-input"
                  />
                  {uploadedFile && (
                    <div className="file-info" style={{ marginTop: "8px" }}>
                      <span className="file-name">{uploadedFile.name}</span>
                      <span className="file-size">
                        ({(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB)
                      </span>
                    </div>
                  )}
                  <p style={{ fontSize: "11px", color: "var(--neon-green)", margin: "8px 0 0 0", fontFamily: "var(--font-mono)" }}>
                    ⚡ Uploading an APK automatically launches the Android sandbox & opens the phone window.
                  </p>
                </div>

                <div style={{ marginBottom: "18px" }}>
                  <label style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-muted)", display: "block", marginBottom: "8px", textTransform: "uppercase" }}>
                    Observation Duration:
                  </label>
                  <select
                    value={dynamicDuration}
                    onChange={(e) => setDynamicDuration(Number(e.target.value))}
                    disabled={isRunning}
                    style={{
                      width: "100%",
                      padding: "10px 14px",
                      borderRadius: "0",
                      background: "#050505",
                      color: "var(--text-main)",
                      border: "1px solid var(--card-border)",
                      fontSize: "12px",
                      fontFamily: "var(--font-mono)"
                    }}
                  >
                    <option value={10}>10 Seconds (Fast audit)</option>
                    <option value={15}>15 Seconds (Recommended)</option>
                    <option value={30}>30 Seconds (Deep beacon capture)</option>
                  </select>
                </div>

                <button
                  onClick={() => handleDynamicRun(uploadedFile)}
                  disabled={isRunning || (!uploadedFile && !apkId)}
                  className="btn btn-primary"
                  style={{ width: "100%", justifyContent: "center" }}
                >
                  {isRunning ? "⏳ Sandbox Running..." : "🚀 Launch Sandbox (Opens Phone)"}
                </button>
              </div>
            )}

            <PipelineStepper
              stages={stages}
              currentStageIndex={currentStageIndex}
              onSelectStage={(idx) => setCurrentStageIndex(idx)}
              isRunning={isRunning}
              hasApk={Boolean(apkId || uploadedFile)}
            />
          </div>

          <div className="main-panel-col" style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            {!isDynamic && stageResults[8] && (
              <RiskBanner correlationData={stageResults[8].risk_analysis} />
            )}

            {isDynamic && dynamicResults[5] && (
              <div style={{
                background: "#080808",
                border: (dynamicResults[5].risk_assessment?.risk_score || 0) >= 50 ? "2px solid var(--danger-red)" : "2px solid var(--neon-green)",
                borderRadius: "0",
                padding: "20px 24px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center"
              }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: "15px", fontFamily: "var(--font-mono)", fontWeight: "900", color: (dynamicResults[5].risk_assessment?.risk_score || 0) >= 50 ? "#f87171" : "var(--neon-green)", textTransform: "uppercase", letterSpacing: "1px" }}>
                    Dynamic Analysis Verdict
                  </h3>
                  <p style={{ margin: "6px 0 0 0", fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                    RISK LEVEL: <strong style={{ color: (dynamicResults[5].risk_assessment?.risk_score || 0) >= 50 ? "var(--danger-red)" : "var(--neon-green)" }}>
                      {dynamicResults[5].risk_assessment?.risk_label || "LOW RISK"}
                    </strong>
                  </p>
                </div>
                <div style={{ fontSize: "36px", fontWeight: "1000", fontFamily: "var(--font-mono)", color: (dynamicResults[5].risk_assessment?.risk_score || 0) >= 50 ? "var(--danger-red)" : "var(--neon-green)" }}>
                  {dynamicResults[5].risk_assessment?.risk_score ?? 0} / 100
                </div>
              </div>
            )}

            {isDynamic ? (
              <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: "24px", alignItems: "start" }}>
                <LiveVirtualDevice
                  activePackageName={dynamicResults[1]?.package_name}
                  isRunning={isRunning}
                />
                <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                  <ResultsPanel
                    stageName={stages[currentStageIndex]?.title || "Inspection View"}
                    data={currentResults}
                    stageId={stages[currentStageIndex]?.id}
                  />
                </div>
              </div>
            ) : (
              <ResultsPanel
                stageName={stages[currentStageIndex]?.title || "Inspection View"}
                data={currentResults}
                stageId={stages[currentStageIndex]?.id}
              />
            )}

            {!isDynamic && stageResults[9] && currentStageIndex === 9 && (
              <ReportViewer apkId={apkId} />
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
