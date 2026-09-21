import React from "react";
import { getReportViewUrl, getReportDownloadUrl } from "../api/client";

export default function ReportViewer({ apkId }) {
  if (!apkId) return null;

  const viewUrl = getReportViewUrl(apkId);
  const downloadUrl = getReportDownloadUrl(apkId);

  return (
    <div className="card report-card">
      <div className="card-header">
        <h3 className="card-title">7. Final Forensic Artifact Report</h3>
        <div className="report-actions">
          <a
            href={downloadUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-primary btn-sm"
          >
            📥 Download PDF Report
          </a>
          <a
            href={viewUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-outline btn-sm"
          >
            ↗ Open HTML Report
          </a>
        </div>
      </div>

      <div className="iframe-container">
        <iframe
          src={viewUrl}
          title="Forensic Report View"
          className="report-iframe"
        />
      </div>
    </div>
  );
}
