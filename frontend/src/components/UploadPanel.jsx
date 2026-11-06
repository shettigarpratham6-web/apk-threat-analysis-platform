import React, { useState } from "react";

export default function UploadPanel({ onUpload, onDynamicUpload, isRunning }) {
  const [selectedFile, setSelectedFile] = useState(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleUpload = () => {
    if (selectedFile) {
      onUpload(selectedFile);
    }
  };

  const handleDynamic = () => {
    if (selectedFile && onDynamicUpload) {
      onDynamicUpload(selectedFile);
    }
  };

  return (
    <div className="card upload-card">
      <div className="card-header">
        <h2 className="card-title">1. APK Ingestion</h2>
        <span className="card-badge">Stage 1</span>
      </div>
      <p className="card-desc">
        Select an Android APK file to inspect via static decompilation or launch live inside the fake phone sandbox.
      </p>

      <div className="upload-controls">
        <input
          type="file"
          accept=".apk"
          id="apk-file-input"
          onChange={handleFileChange}
          disabled={isRunning}
          className="file-input"
        />

        {selectedFile && (
          <div className="file-info">
            <span className="file-name">{selectedFile.name}</span>
            <span className="file-size">
              ({(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)
            </span>
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "12px", width: "100%" }}>
          <button
            onClick={handleUpload}
            disabled={!selectedFile || isRunning}
            className="btn btn-primary"
            style={{ width: "100%", justifyContent: "center" }}
          >
            {isRunning ? "Pipeline Running..." : "🔍 Run Static Decompilation"}
          </button>

          <button
            onClick={handleDynamic}
            disabled={!selectedFile || isRunning}
            className="btn btn-secondary"
            style={{ width: "100%", justifyContent: "center", background: "#7c3aed", color: "#ffffff", border: "none" }}
          >
            🚀 Launch in Fake Phone Sandbox
          </button>
        </div>
      </div>
    </div>
  );
}
