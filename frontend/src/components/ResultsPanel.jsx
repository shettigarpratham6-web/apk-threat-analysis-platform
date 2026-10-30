import React, { useState } from "react";

export default function ResultsPanel({ stageName, data, stageId }) {
  const [showRawJson, setShowRawJson] = useState(false);

  if (!data) {
    return (
      <div className="card results-card empty-results">
        <h3>Stage Inspection View: {stageName}</h3>
        <p className="text-muted">No analysis output generated for this stage yet. Run the pipeline to inspect results.</p>
      </div>
    );
  }

  const renderTree = (treeList) => {
    if (!treeList || !treeList.length) return <p>No files extracted.</p>;
    return (
      <div className="tree-explorer code-font">
        {treeList.map((node, i) => {
          const depth = (node.match(/\//g) || []).length;
          const isDir = node.endsWith("/");
          return (
            <div key={i} style={{ paddingLeft: `${depth * 20}px` }}>
              {isDir ? "📁 " : "📄 "}{node}
            </div>
          );
        })}
      </div>
    );
  };

  const renderPermissions = (permissions) => {
    if (!permissions || permissions.length === 0) return <p>No permissions found.</p>;
    return (
      <div className="permission-badges">
        {permissions.map((p, i) => {
          let badgeColor = "bg-green";
          if (p.severity === "Critical") badgeColor = "bg-red";
          if (p.severity === "High") badgeColor = "bg-orange";
          if (p.severity === "Medium") badgeColor = "bg-yellow";
          return (
            <div key={i} className={`badge-card ${badgeColor}`} style={{ padding: "10px", margin: "5px", borderRadius: "5px", border: "1px solid #ccc" }}>
              <strong>{p.name.replace("android.permission.", "")}</strong> ({p.severity})
              <p style={{fontSize:"12px", margin:"5px 0 0 0"}}>{p.reason}</p>
            </div>
          );
        })}
      </div>
    );
  };

  const renderStageContent = () => {
    if (stageId === "upload") {
      return (
        <div className="metrics-grid">
          <div className="metric-box">
            <span className="metric-label">Filename</span>
            <span className="metric-value">{data.metadata?.filename}</span>
          </div>
          <div className="metric-box">
            <span className="metric-label">Size</span>
            <span className="metric-value">{(data.metadata?.size / 1024 / 1024).toFixed(2)} MB</span>
          </div>
          <div className="metric-box">
            <span className="metric-label">SHA256</span>
            <span className="metric-value code-font" style={{fontSize: "12px"}}>{data.metadata?.sha256}</span>
          </div>
        </div>
      );
    }
    
    if (stageId === "extract") {
      return (
        <div className="results-section">
          <h4>Extracted File Tree</h4>
          <div style={{background: "#1e1e1e", color: "#d4d4d4", padding: "15px", borderRadius: "8px", maxHeight: "400px", overflowY: "auto"}}>
            <div>suspicious_app.apk</div>
            <div>│</div>
            <div>▼ unzip</div>
            <div>│</div>
            {renderTree(data.extraction?.tree)}
          </div>
        </div>
      );
    }
    
    if (stageId === "manifest") {
      return (
        <div>
           <h4>APK Metadata</h4>
           <p>Package: {data.manifest?.metadata?.package_name}</p>
           <p>Version: {data.manifest?.metadata?.version_name}</p>
           <p>Min SDK: {data.manifest?.metadata?.min_sdk}</p>
           
           <h4>Security Flags</h4>
           <pre>{JSON.stringify(data.manifest?.security_flags, null, 2)}</pre>
           
           <h4>Components (Summary)</h4>
           <p>Activities: {data.manifest?.components?.activities?.length || 0}</p>
           <p>Services: {data.manifest?.components?.services?.length || 0}</p>
           <p>Receivers: {data.manifest?.components?.receivers?.length || 0}</p>
        </div>
      );
    }

    if (stageId === "permissions") {
      return (
        <div className="results-section">
          <h4>Permission Analysis</h4>
          {renderPermissions(data.permissions)}
        </div>
      );
    }

    if (stageId === "code") {
      return (
        <div>
          <h4>Network Indicators</h4>
          <p>URLs: {data.code_analysis?.network_indicators?.urls?.length || 0}</p>
          <p>IPs: {data.code_analysis?.network_indicators?.ipv4?.length || 0}</p>
          
          <h4>Suspicious APIs ({data.code_analysis?.suspicious_apis?.length || 0})</h4>
          <table className="results-table">
              <thead><tr><th>Class</th><th>API</th><th>Severity</th></tr></thead>
              <tbody>
                  {(data.code_analysis?.suspicious_apis || []).map((api, i) => (
                      <tr key={i}><td>{api.class_name}</td><td>{api.api}</td><td>{api.severity}</td></tr>
                  ))}
              </tbody>
          </table>
          
          <h4>Malware Indicators ({data.code_analysis?.malware_indicators?.length || 0})</h4>
          <ul style={{textAlign: "left"}}>
              {(data.code_analysis?.malware_indicators || []).map((ind, i) => (
                  <li key={i}><strong>{ind.severity}</strong>: {ind.why_flagged}</li>
              ))}
          </ul>
          
          <h4>Obfuscation & High Entropy Findings</h4>
          <table className="results-table">
              <thead><tr><th>Value</th><th>Entropy</th><th>Reason</th></tr></thead>
              <tbody>
                  {(data.code_analysis?.obfuscation_findings || []).map((obf, i) => (
                      <tr key={i}>
                          <td className="code-font">{obf.value}</td>
                          <td>{obf.entropy}</td>
                          <td>{obf.reason}</td>
                      </tr>
                  ))}
              </tbody>
          </table>

          {/* CodeBERT Pretrained Semantic Similarity Analysis */}
          {(() => {
            const codebert = data.codebert_similarity || data.code_analysis?.codebert_similarity;
            const matches = codebert?.matches || [];
            return (
              <div style={{marginTop: "24px", padding: "16px", borderRadius: "8px", background: "rgba(59, 130, 246, 0.05)", border: "1px solid rgba(59, 130, 246, 0.2)"}}>
                <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "8px"}}>
                  <h4 style={{margin: 0, display: "flex", alignItems: "center", gap: "8px", color: "#60a5fa"}}>
                    <span>🧠</span> CodeBERT Suspicious Code Semantic Similarity ({codebert?.model || "microsoft/codebert-base"})
                  </h4>
                  <span className={`badge ${codebert?.status === "active" ? "badge-primary" : "badge-warning"}`} style={{fontSize: "11px", padding: "4px 8px"}}>
                    {codebert?.status === "active" ? "Model Active • 16GB RAM Optimized" : "Heuristic Fallback"}
                  </span>
                </div>

                <p style={{fontSize: "12px", color: "#94a3b8", margin: "0 0 14px 0", lineHeight: "1.5"}}>
                  Pretrained CodeBERT analyzes extracted Java/Kotlin/Smali code for structural and functional similarity to known suspicious Android behavioral patterns.
                  <em style={{display: "block", marginTop: "4px", color: "#cbd5e1"}}>Note: Measures semantic similarity to reference patterns; does not claim autonomous malware classification without a validated classifier.</em>
                </p>

                {matches.length > 0 ? (
                  <table className="results-table">
                    <thead>
                      <tr>
                        <th>Pattern / Behavior</th>
                        <th>Category</th>
                        <th>Confidence</th>
                        <th>Evidence Location & Snippet</th>
                      </tr>
                    </thead>
                    <tbody>
                      {matches.map((m, idx) => (
                        <tr key={idx}>
                          <td>
                            <strong>{m.pattern_name}</strong>
                            <div style={{fontSize: "11px", color: "#94a3b8", marginTop: "2px"}}>{m.description}</div>
                          </td>
                          <td><span className="badge" style={{background: "rgba(255,255,255,0.08)", padding: "3px 6px"}}>{m.category}</span></td>
                          <td>
                            <span style={{
                              fontWeight: "bold",
                              color: m.confidence_score >= 0.8 ? "#ef4444" : (m.confidence_score >= 0.65 ? "#f59e0b" : "#3b82f6")
                            }}>
                              {m.similarity_percentage || `${(m.confidence_score * 100).toFixed(1)}%`}
                            </span>
                          </td>
                          <td style={{fontSize: "12px"}}>
                            <div><strong>Class:</strong> {m.evidence?.class_name}</div>
                            <div style={{color: "#94a3b8"}}><strong>File:</strong> {m.evidence?.file_path}</div>
                            {m.evidence?.snippet && (
                              <pre className="code-font" style={{fontSize: "10px", margin: "4px 0 0 0", padding: "4px", background: "rgba(0,0,0,0.3)", borderRadius: "4px", whiteSpace: "pre-wrap", maxHeight: "60px", overflowY: "auto"}}>
                                {m.evidence.snippet}
                              </pre>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{fontSize: "13px", color: "#94a3b8", margin: "8px 0 0 0"}}>
                    No suspicious behavioral similarities matched above the confidence threshold.
                  </p>
                )}
              </div>
            );
          })()}
        </div>
      );
    }

    if (stageId === "resources") {
      return (
        <div>
          <h4>Exposed Secrets ({data.resource_analysis?.secrets?.length || 0})</h4>
          <table className="results-table">
              <thead><tr><th>File</th><th>Type</th><th>Value</th></tr></thead>
              <tbody>
                  {(data.resource_analysis?.secrets || []).map((sec, i) => (
                      <tr key={i}><td>{sec.file}</td><td>{sec.type}</td><td className="code-font">{sec.value}</td></tr>
                  ))}
              </tbody>
          </table>
        </div>
      );
    }

    if (stageId === "native") {
      return (
        <div>
          <h4>Native Architectures</h4>
          <p>{(data.native_library_analysis?.architectures || []).join(", ") || "None"}</p>
          
          <h4>Suspicious Libraries</h4>
          <ul>
              {(data.native_library_analysis?.suspicious_libraries || []).map((lib, i) => (
                  <li key={i}>{lib.name} - {lib.reasons?.join(", ")}</li>
              ))}
          </ul>
        </div>
      );
    }

    if (stageId === "yara") {
      return (
        <div>
          <h4>YARA Matches ({data.yara_matches?.length || 0})</h4>
          {data.yara_matches && data.yara_matches.length > 0 ? (
             <table className="results-table">
                 <thead><tr><th>Rule</th><th>Severity</th><th>File</th></tr></thead>
                 <tbody>
                     {data.yara_matches.map((m, i) => (
                         <tr key={i}><td>{m.rule_name}</td><td>{m.severity}</td><td>{m.matched_file}</td></tr>
                     ))}
                 </tbody>
             </table>
          ) : (
             <p className="text-muted">No known malware signatures detected.</p>
          )}
        </div>
      );
    }
    
    if (stageId === "risk") {
      const codebertData = data.codebert_similarity || data.code_analysis?.codebert_similarity;
      return (
        <div>
          <h4>Threat Correlation Engine</h4>
          <div style={{display: "flex", alignItems: "center", gap: "20px", marginBottom: "20px"}}>
             <div style={{fontSize: "48px", fontWeight: "bold", color: data.risk_analysis?.level === "Critical" ? "red" : "orange"}}>
                {data.risk_analysis?.score} / 100
             </div>
             <div style={{fontSize: "24px"}}>{data.risk_analysis?.level} Risk</div>
          </div>
          {data.ml_classification && (
            <div style={{marginTop: "15px", marginBottom: "20px", padding: "14px", borderRadius: "8px", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.1)"}}>
              <h4 style={{margin: "0 0 10px 0", display: "flex", alignItems: "center", gap: "8px"}}>
                <span>🤖</span> Machine Learning Malware Classifier (Random Forest)
              </h4>
              <div className="metrics-grid" style={{marginBottom: "10px"}}>
                <div className="metric-box">
                  <span className="metric-label">Prediction</span>
                  <span className="metric-value" style={{color: data.ml_classification.prediction === "malware" ? "#ef4444" : "#22c55e", textTransform: "capitalize"}}>
                    {data.ml_classification.prediction}
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Malware Probability</span>
                  <span className="metric-value">
                    {((data.ml_classification.malware_probability || 0) * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Features Matched</span>
                  <span className="metric-value">
                    {data.ml_classification.active_features_count ?? (data.ml_classification.active_features?.length || 0)}
                  </span>
                </div>
              </div>
              {data.ml_classification.active_features && data.ml_classification.active_features.length > 0 && (
                <div style={{fontSize: "12px", color: "var(--text-secondary, #94a3b8)"}}>
                  <strong style={{color: "var(--text-primary, #f1f5f9)"}}>Key Triggered Indicators:</strong>{" "}
                  {data.ml_classification.active_features.slice(0, 8).join(", ")}
                  {data.ml_classification.active_features.length > 8 ? "..." : ""}
                </div>
              )}
            </div>
          )}

          {codebertData && (
            <div style={{marginTop: "15px", marginBottom: "20px", padding: "14px", borderRadius: "8px", background: "rgba(59, 130, 246, 0.05)", border: "1px solid rgba(59, 130, 246, 0.2)"}}>
              <h4 style={{margin: "0 0 10px 0", display: "flex", alignItems: "center", gap: "8px", color: "#60a5fa"}}>
                <span>🧠</span> CodeBERT Suspicious Code Semantic Analysis
              </h4>
              <div className="metrics-grid" style={{marginBottom: "10px"}}>
                <div className="metric-box">
                  <span className="metric-label">Model Engine</span>
                  <span className="metric-value" style={{fontSize: "14px"}}>
                    {codebertData.model || "microsoft/codebert-base"}
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Behavioral Matches</span>
                  <span className="metric-value">
                    {codebertData.suspicious_matches_found ?? (codebertData.matches?.length || 0)}
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Peak Confidence</span>
                  <span className="metric-value">
                    {((codebertData.max_confidence_score || 0) * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
              <p style={{fontSize: "12px", color: "#94a3b8", margin: 0}}>
                {codebertData.disclaimer || "Pretrained CodeBERT identifies structural similarity to known suspicious behaviors, distinct from malware classification."}
              </p>
            </div>
          )}

          <h4>Risk Factors</h4>
          <ul>
             {(data.risk_analysis?.factors || []).map((f, i) => <li key={i}>{f}</li>)}
          </ul>
          
          <h4 style={{marginTop: "20px"}}>Certificates</h4>
          <table className="results-table">
              <thead><tr><th>Issuer</th><th>SHA1</th><th>Self-Signed</th></tr></thead>
              <tbody>
                  {(data.certificate_analysis || []).map((cert, i) => (
                      <tr key={i}>
                          <td>{cert.issuer}</td>
                          <td className="code-font" style={{fontSize: "12px"}}>{cert.sha1}</td>
                          <td>{cert.self_signed ? "Yes" : "No"}</td>
                      </tr>
                  ))}
              </tbody>
          </table>
          
          <h4 style={{marginTop: "20px"}}>Aggregated IOCs</h4>
          <div className="metrics-grid">
              <div className="metric-box">
                  <span className="metric-label">URLs</span>
                  <span className="metric-value">{data.iocs?.network?.urls?.length || 0}</span>
              </div>
              <div className="metric-box">
                  <span className="metric-label">IPs</span>
                  <span className="metric-value">{data.iocs?.network?.ipv4?.length || 0}</span>
              </div>
              <div className="metric-box">
                  <span className="metric-label">Secrets</span>
                  <span className="metric-value">{data.iocs?.secrets?.length || 0}</span>
              </div>
          </div>
        </div>
      );
    }

    return null;
  };

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

      <div style={{padding: "15px"}}>
         {renderStageContent()}
      </div>

      {showRawJson && (
        <div className="json-container">
          <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
