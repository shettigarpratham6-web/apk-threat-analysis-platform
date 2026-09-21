import React, { useState } from "react";
import "./App.css";

import UploadPanel from "./components/UploadPanel";
import PipelineStepper from "./components/PipelineStepper";
import ResultsPanel from "./components/ResultsPanel";
import RiskBanner from "./components/RiskBanner";
import ReportViewer from "./components/ReportViewer";

import { uploadAndAnalyzeStatic } from "./api/client";

const STATIC_STAGES = [
  { id: "upload", title: "1. Upload APK", subtitle: "Submit file to backend", status: "pending" },
  { id: "extract", title: "2. Extract APK", subtitle: "Secure unzip & tree generation", status: "pending" },
  { id: "manifest", title: "3. Manifest Scan", subtitle: "Permissions & Components", status: "pending" },
  { id: "permissions", title: "4. Permission Analysis", subtitle: "Risk categorization", status: "pending" },
  { id: "code", title: "5. DEX Code Scan", subtitle: "URLs, IPs & Suspicious APIs", status: "pending" },
  { id: "resources", title: "6. Resource Scan", subtitle: "Secrets & API Keys", status: "pending" },
  { id: "native", title: "7. Native Library Scan", subtitle: "ABI & Suspicious SOs", status: "pending" },
  { id: "yara", title: "8. YARA Scan", subtitle: "Signature matching", status: "pending" },
  { id: "risk", title: "9. Risk Correlation", subtitle: "Threat scoring", status: "pending" },
  { id: "report", title: "10. Threat Report", subtitle: "Forensic documentation", status: "pending" },
];

export default function App() {
  const [stages, setStages] = useState(STATIC_STAGES);
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [apkId, setApkId] = useState(null);
  const [stageResults, setStageResults] = useState({});
  const [globalError, setGlobalError] = useState(null);
  const [isRunning, setIsRunning] = useState(false);

  const updateStageStatus = (index, status) => {
    setStages((prev) => {
      const copy = [...prev];
      if (copy[index]) {
          copy[index] = { ...copy[index], status };
      }
      return copy;
    });
  };

  const handleUploadAndAnalyze = async (file) => {
    if (!file) {
      setGlobalError("Please select a valid .apk file first.");
      return;
    }
    setGlobalError(null);
    setIsRunning(true);
    setStages(STATIC_STAGES.map(s => ({ ...s, status: "pending" })));
    setStageResults({});
    setCurrentStageIndex(0);
    updateStageStatus(0, "running");

    // Artificial animation of stages while API loads
    let fakeIdx = 1;
    const fakeInterval = setInterval(() => {
        if(fakeIdx < 7) {
            updateStageStatus(fakeIdx - 1, "completed");
            updateStageStatus(fakeIdx, "running");
            setCurrentStageIndex(fakeIdx);
            fakeIdx++;
        }
    }, 3000); // 3 seconds per stage

    try {
      const data = await uploadAndAnalyzeStatic(file);
      clearInterval(fakeInterval);
      
      setApkId(data.apk_id);

      // Map backend results to frontend stages
      const mappedResults = {
        0: { metadata: data.metadata },
        1: { extraction: data.extraction },
        2: { manifest: data.manifest_analysis },
        3: { permissions: data.manifest_analysis?.permissions },
        4: { code_analysis: data.code_analysis },
        5: { resource_analysis: data.resource_analysis },
        6: { native_library_analysis: data.native_library_analysis },
        7: { yara_matches: data.yara_matches },
        8: { risk_analysis: data.risk_analysis },
        9: { report: true, apkId: data.apk_id }
      };

      setStageResults(mappedResults);

      // Rapidly complete remaining stages
      const delay = (ms) => new Promise(res => setTimeout(res, ms));
      for(let i = fakeIdx - 1; i < STATIC_STAGES.length; i++) {
        setCurrentStageIndex(i);
        updateStageStatus(i, "running");
        await delay(600);
        updateStageStatus(i, "completed");
      }
      setCurrentStageIndex(9); // end at report
    } catch (err) {
      clearInterval(fakeInterval);
      setGlobalError(`Analysis failed: ${err.message}`);
      updateStageStatus(fakeIdx - 1, "error");
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <div className="header-brand">
          <span className="brand-icon">🛡️</span>
          <div>
            <h1 className="brand-title">APK Threat Analysis Platform</h1>
            <p className="brand-subtitle">
              Automated Static Analysis & Cyber-Forensic Inspection System
            </p>
          </div>
        </div>
        <div className="header-status">
          <span className="status-dot"></span>
          <span>System Backend Connected</span>
        </div>
      </header>

      <main className="main-content">
        {globalError && <div className="error-banner">{globalError}</div>}

        <div className="dashboard-grid">
          <div className="sidebar-col" style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            <UploadPanel
              onUpload={handleUploadAndAnalyze}
              isRunning={isRunning}
            />

            <PipelineStepper
              stages={stages}
              currentStageIndex={currentStageIndex}
              onSelectStage={(idx) => setCurrentStageIndex(idx)}
              isRunning={isRunning}
              hasApk={Boolean(apkId)}
            />
          </div>

          <div className="main-panel-col" style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            {stageResults[8] && <RiskBanner correlationData={stageResults[8].risk_analysis} />}

            <ResultsPanel
              stageName={stages[currentStageIndex]?.title || "Inspection View"}
              data={stageResults[currentStageIndex]}
              stageId={stages[currentStageIndex]?.id}
            />

            {stageResults[9] && currentStageIndex === 9 && <ReportViewer apkId={apkId} />}
          </div>
        </div>
      </main>
    </div>
  );
}
