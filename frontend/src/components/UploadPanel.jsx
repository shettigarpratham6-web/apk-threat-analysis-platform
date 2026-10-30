import React, { useState } from "react";

export default function UploadPanel({ onUpload, isRunning }) {
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

  return (
    <div className="card upload-card">
      <div className="card-header">
        <h2 className="card-title">1. APK Ingestion</h2>
        <span className="card-badge">Stage 1</span>
      </div>
      <p className="card-desc">
        Select an Android APK file to upload and execute the automated static analysis pipeline.
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

        <button
          onClick={handleUpload}
          disabled={!selectedFile || isRunning}
          className="btn btn-primary"
        >
          {isRunning ? "Pipeline Running..." : "Start Pipeline Analysis"}
        </button>
      </div>
    </div>
  );
}
