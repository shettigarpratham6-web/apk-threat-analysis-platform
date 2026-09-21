import React, { useEffect, useState } from "react";
import { generateReport, getReportViewUrl, getReportDownloadUrl, getReportJsonDownloadUrl, getReportIocJsonUrl, getReportIocCsvUrl } from "../api/client";

export default function ReportViewer({ apkId }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!apkId) return;
    
    // Automatically trigger generation when mounting
    generateReport(apkId)
      .then(() => setLoading(false))
      .catch((err) => {
          setError(err.message);
          setLoading(false);
      });
  }, [apkId]);

  if (!apkId) return null;

  const viewUrl = getReportViewUrl(apkId);
  const downloadUrl = getReportDownloadUrl(apkId);
  const jsonUrl = getReportJsonDownloadUrl(apkId);
  const iocJsonUrl = getReportIocJsonUrl(apkId);
  const iocCsvUrl = getReportIocCsvUrl(apkId);

  return (
    <div className="card report-card">
      <div className="card-header">
        <h3 className="card-title">10. Final Forensic Artifact Report</h3>
        {!loading && !error && (
            <div className="report-actions" style={{display: "flex", gap: "10px", flexWrap: "wrap"}}>
              <a href={viewUrl} target="_blank" rel="noopener noreferrer" className="btn btn-outline btn-sm">
                ↗ View HTML
              </a>
              <a href={downloadUrl} target="_blank" rel="noopener noreferrer" className="btn btn-primary btn-sm">
                📥 Download PDF
              </a>
              <a href={jsonUrl} target="_blank" rel="noopener noreferrer" className="btn btn-secondary btn-sm">
                📥 Download JSON
              </a>
              <a href={iocJsonUrl} target="_blank" rel="noopener noreferrer" className="btn btn-accent btn-sm">
                📥 Download IOC JSON
              </a>
              <a href={iocCsvUrl} target="_blank" rel="noopener noreferrer" className="btn btn-accent btn-sm">
                📥 Download IOC CSV
              </a>
            </div>
        )}
      </div>

      <div className="iframe-container" style={{ minHeight: "600px", border: "1px solid #334155", borderRadius: "8px", overflow: "hidden", marginTop: "15px" }}>
        {loading && (
            <div style={{padding: "50px", textAlign: "center"}}>
                <div style={{fontSize: "40px", marginBottom: "20px"}}>⏳</div>
                <h3>Generating Professional Forensic Report...</h3>
                <p className="text-muted">Compiling PDF and rendering HTML artifacts.</p>
            </div>
        )}
        
        {error && (
            <div style={{padding: "50px", textAlign: "center", color: "#ef4444"}}>
                <h3>Failed to generate report</h3>
                <p>{error}</p>
            </div>
        )}

        {!loading && !error && (
            <iframe
              src={viewUrl}
              title="Forensic Report View"
              className="report-iframe"
              style={{ width: "100%", height: "100%", minHeight: "600px", border: "none" }}
            />
        )}
      </div>
    </div>
  );
}
