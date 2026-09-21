import React, { useState } from "react";

export default function ResultsPanel({ stageName, data }) {
  const [showRawJson, setShowRawJson] = useState(false);

  if (!data) {
    return (
      <div className="card results-card empty-results">
        <h3>Stage Inspection View: {stageName}</h3>
        <p className="text-muted">No analysis output generated for this stage yet. Run the stage to inspect results.</p>
      </div>
    );
  }

  return (
    <div className="card results-card">
      <div className="card-header">
        <h3 className="card-title">Output Inspection: {stageName}</h3>
        <button
          className="btn btn-outline btn-sm"
          onClick={() => setShowRawJson(!showRawJson)}
        >
          {showRawJson ? "Hide Raw JSON" : "View Raw JSON"}
        </button>
      </div>

      {/* Render Summary Metrics based on stage type */}
      {data.static_analysis && (
        <div className="metrics-grid">
          <div className="metric-box">
            <span className="metric-label">Package Name</span>
            <span className="metric-value code-font">
              {data.static_analysis.manifest?.package_name || "N/A"}
            </span>
          </div>
          <div className="metric-box">
            <span className="metric-label">Permissions</span>
            <span className="metric-value">
              {data.static_analysis.manifest?.requested_permissions?.length || 0} (
              {data.static_analysis.manifest?.declared_dangerous_permissions?.length || 0} dangerous)
            </span>
          </div>
          <div className="metric-box">
            <span className="metric-label">Extracted URLs / IPs</span>
            <span className="metric-value">
              {data.static_analysis.code_analysis?.urls?.length || 0} /{" "}
              {data.static_analysis.code_analysis?.ip_addresses?.length || 0}
            </span>
          </div>
          <div className="metric-box">
            <span className="metric-label">YARA Matches</span>
            <span className="metric-value highlight-red">
              {data.static_analysis.signature_check?.yara_matches?.length || 0}
            </span>
          </div>
        </div>
      )}

      {data.dynamic_analysis && (
        <div className="metrics-grid">
          <div className="metric-box">
            <span className="metric-label">Network Traffic Flows</span>
            <span className="metric-value">
              {data.dynamic_analysis.network_traffic?.length || 0} entries
            </span>
          </div>
          <div className="metric-box">
            <span className="metric-label">File Operations</span>
            <span className="metric-value">
              {data.dynamic_analysis.file_activity?.length || 0} events
            </span>
          </div>
          <div className="metric-box">
            <span className="metric-label">API Calls</span>
            <span className="metric-value">
              {data.dynamic_analysis.api_calls?.length || 0} calls
            </span>
          </div>
        </div>
      )}

      {data.suspected_c2_hosts && (
        <div className="results-section">
          <h4>Suspected C2 Communication Targets ({data.suspected_c2_hosts.length})</h4>
          {data.suspected_c2_hosts.length === 0 ? (
            <p className="text-muted">No suspicious beaconing or raw IP C2 hosts flagged.</p>
          ) : (
            <table className="results-table">
              <thead>
                <tr>
                  <th>Host Target</th>
                  <th>Confidence</th>
                  <th>Detection Reasons</th>
                </tr>
              </thead>
              <tbody>
                {data.suspected_c2_hosts.map((host, idx) => (
                  <tr key={idx}>
                    <td className="code-font">{host.host}</td>
                    <td>
                      <span className={`badge badge-${host.confidence}`}>
                        {host.confidence}
                      </span>
                    </td>
                    <td>
                      <ul className="reasons-list">
                        {host.reasons?.map((r, rIdx) => (
                          <li key={rIdx}>{r}</li>
                        ))}
                      </ul>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {data.checked && (
        <div className="results-section">
          <h4>External Server Reputation Verdicts ({data.checked.length})</h4>
          {data.checked.length === 0 ? (
            <p className="text-muted">No server hosts evaluated.</p>
          ) : (
            <table className="results-table">
              <thead>
                <tr>
                  <th>Host Target</th>
                  <th>Type</th>
                  <th>Verdict</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {data.checked.map((s, idx) => (
                  <tr key={idx}>
                    <td className="code-font">{s.host}</td>
                    <td>{s.type?.toUpperCase()}</td>
                    <td>
                      <span className={`badge badge-${s.verdict}`}>
                        {s.verdict}
                      </span>
                    </td>
                    <td className="small-text">{s.reputation?.reason || "Enriched threat lookup"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Raw JSON View */}
      {showRawJson && (
        <div className="json-container">
          <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
