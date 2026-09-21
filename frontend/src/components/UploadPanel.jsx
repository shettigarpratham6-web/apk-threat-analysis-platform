import React, { useState } from "react";
import { uploadAndAnalyzeStatic } from "../api/client";

export default function UploadPanel({ onUploadSuccess, onError }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      if (onError) onError("Please select a valid .apk file first.");
      return;
    }

    setLoading(true);
    try {
      const data = await uploadAndAnalyzeStatic(selectedFile);
      setLoading(false);
      if (onUploadSuccess) {
        onUploadSuccess(data);
      }
    } catch (err) {
      setLoading(false);
      if (onError) {
        onError(`Upload failed: ${err.message}`);
      }
    }
  };

  return (
    <div className="card upload-card">
      <div className="card-header">
        <h2 className="card-title">1. APK Ingestion & Inital Static Scan</h2>
        <span className="card-badge">Stage 1</span>
      </div>
      <p className="card-desc">
        Select an Android APK file to upload into the platform sandbox directory and execute automated manifest, DEX bytecode, YARA, and signature scans.
      </p>

      <div className="upload-controls">
        <input
          type="file"
          accept=".apk"
          id="apk-file-input"
          onChange={handleFileChange}
          disabled={loading}
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
          disabled={!selectedFile || loading}
          className="btn btn-primary"
        >
          {loading ? "Analyzing APK..." : "Start Pipeline Analysis"}
        </button>
      </div>
    </div>
  );
}
