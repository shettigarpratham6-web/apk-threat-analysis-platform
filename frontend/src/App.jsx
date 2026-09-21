import React, { useState } from "react";
import "./App.css";

import UploadPanel from "./components/UploadPanel";
import PipelineStepper from "./components/PipelineStepper";
import ResultsPanel from "./components/ResultsPanel";
import RiskBanner from "./components/RiskBanner";
import ReportViewer from "./components/ReportViewer";

import {
  startSandbox,
  runApk,
  monitorBehavior,
  detectC2,
  checkServers,
  correlate,
  generateReport,
} from "./api/client";

const INITIAL_STAGES = [
  {
    id: "static",
    title: "1. Static Analysis",
    subtitle: "Manifest, Code Scan, YARA & Signatures",
    status: "pending",
  },
  {
    id: "sandbox_start",
    title: "2. Launch Sandbox",
    subtitle: "Spawn Android Emulator & Poll ADB",
    status: "pending",
  },
  {
    id: "apk_run",
    title: "3. Run APK Safely",
    subtitle: "Install & Launch target package",
    status: "pending",
  },
  {
    id: "monitor",
    title: "4. Behavior Monitoring",
    subtitle: "mitmproxy traffic & Frida API hooks",
    status: "pending",
  },
  {
    id: "c2_detect",
    title: "5. C2 Detection",
    subtitle: "Beaconing & raw IP pattern heuristic",
    status: "pending",
  },
  {
    id: "servers",
    title: "6. Suspicious Servers",
    subtitle: "AbuseIPDB & VirusTotal reputation",
    status: "pending",
  },
  {
    id: "correlation_report",
    title: "7. Correlation & Report",
    subtitle: "Unified Risk Score & PDF/HTML Report",
    status: "pending",
  },
];

export default function App() {
  const [stages, setStages] = useState(INITIAL_STAGES);
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [apkId, setApkId] = useState(null);
  const [packageName, setPackageName] = useState(null);
  const [stageResults, setStageResults] = useState({});
  const [isRunning, setIsRunning] = useState(false);
  const [globalError, setGlobalError] = useState(null);

  const updateStageStatus = (index, status) => {
    setStages((prev) => {
      const copy = [...prev];
      copy[index] = { ...copy[index], status };
      return copy;
    });
  };

  const handleUploadSuccess = (data) => {
    setGlobalError(null);
    const resolvedApkId = data.apk_id;
    const resolvedPackageName =
      data.static_analysis?.manifest?.package_name ||
      data.static_analysis?.package_name ||
      "com.example.threattest";

    setApkId(resolvedApkId);
    setPackageName(resolvedPackageName);

    setStageResults((prev) => ({
      ...prev,
      0: data,
    }));

    updateStageStatus(0, "completed");
    setCurrentStageIndex(1);
  };

  const executeStage = async (stageIdx) => {
    if (!apkId && stageIdx > 0) {
      setGlobalError("Please upload an APK file first.");
      return null;
    }

    setGlobalError(null);
    setIsRunning(true);
    updateStageStatus(stageIdx, "running");

    try {
      let result = null;

      if (stageIdx === 1) {
        result = await startSandbox();
      } else if (stageIdx === 2) {
        result = await runApk(apkId);
        if (result.package_name) {
          setPackageName(result.package_name);
        }
      } else if (stageIdx === 3) {
        result = await monitorBehavior(apkId, packageName, 5);
      } else if (stageIdx === 4) {
        result = await detectC2(apkId);
      } else if (stageIdx === 5) {
        result = await checkServers(apkId);
      } else if (stageIdx === 6) {
        const corrRes = await correlate(apkId);
        const repRes = await generateReport(apkId);
        result = { ...corrRes, report: repRes };
      }

      setStageResults((prev) => ({
        ...prev,
        [stageIdx]: result,
      }));

      updateStageStatus(stageIdx, "completed");
      setIsRunning(false);
      return result;
    } catch (err) {
      updateStageStatus(stageIdx, "error");
      setGlobalError(`Stage ${stageIdx + 1} Error: ${err.message}`);
      setIsRunning(false);
      throw err;
    }
  };

  const handleRunNextStage = async () => {
    const nextIdx = stages.findIndex((s) => s.status !== "completed");
    if (nextIdx !== -1) {
      setCurrentStageIndex(nextIdx);
      try {
        await executeStage(nextIdx);
        if (nextIdx < stages.length - 1) {
          setCurrentStageIndex(nextIdx + 1);
        }
      } catch (_) {}
    }
  };

  const handleRunAllRemaining = async () => {
    for (let i = 0; i < stages.length; i++) {
      if (stages[i].status !== "completed") {
        setCurrentStageIndex(i);
        try {
          await executeStage(i);
        } catch (_) {
          break;
        }
      }
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
              Automated Static, Sandbox Dynamic & C2 Forensic Inspection System
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
          {/* Left Column: Upload & Pipeline Stepper */}
          <div className="sidebar-col" style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            <UploadPanel
              onUploadSuccess={handleUploadSuccess}
              onError={(err) => setGlobalError(err)}
            />

            <PipelineStepper
              stages={stages}
              currentStageIndex={currentStageIndex}
              onSelectStage={(idx) => setCurrentStageIndex(idx)}
              onRunNextStage={handleRunNextStage}
              onRunAllRemaining={handleRunAllRemaining}
              isRunning={isRunning}
              hasApk={Boolean(apkId)}
            />
          </div>

          {/* Right Column: Stage Inspection, Risk Banner & Final Report */}
          <div className="main-panel-col" style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            {/* Risk Banner (Appears when Stage 6 Correlation is completed) */}
            {stageResults[6] && <RiskBanner correlationData={stageResults[6]} />}

            {/* Results Inspection for Selected Stage */}
            <ResultsPanel
              stageName={stages[currentStageIndex]?.title || "Inspection View"}
              data={stageResults[currentStageIndex]}
            />

            {/* Final Report Viewer (Appears when Stage 6 Correlation/Report is completed) */}
            {stageResults[6] && <ReportViewer apkId={apkId} />}
          </div>
        </div>
      </main>
    </div>
  );
}
