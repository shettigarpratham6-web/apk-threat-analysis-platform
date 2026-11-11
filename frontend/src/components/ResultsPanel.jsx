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
      <div className="permissions-container" style={{display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: "12px"}}>
        {permissions.map((p, i) => {
          let borderColor = "var(--card-border)";
          let badgeBg = "rgba(0, 255, 36, 0.1)";
          let badgeColor = "var(--neon-green)";
          if (p.severity === "Critical") {
            borderColor = "#ef4444";
            badgeBg = "rgba(239, 68, 68, 0.2)";
            badgeColor = "#f87171";
          } else if (p.severity === "High") {
            borderColor = "#f97316";
            badgeBg = "rgba(249, 115, 22, 0.2)";
            badgeColor = "#fb923c";
          } else if (p.severity === "Medium") {
            borderColor = "#eab308";
            badgeBg = "rgba(234, 179, 8, 0.2)";
            badgeColor = "#facc15";
          }

          const cleanName = p.name ? p.name.replace("android.permission.", "") : "PERMISSION";
          return (
            <div key={i} style={{
              padding: "14px 16px",
              borderRadius: "8px",
              background: "rgba(255, 255, 255, 0.02)",
              border: `1px solid ${borderColor}`,
              boxShadow: "0 2px 4px rgba(0,0,0,0.2)"
            }}>
              <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px", flexWrap: "wrap", gap: "6px"}}>
                <span className="code-font" style={{fontWeight: "bold", fontSize: "13px", color: "#f1f5f9"}}>
                  {cleanName}
                </span>
                <div style={{display: "flex", gap: "6px"}}>
                  {p.category && (
                    <span style={{fontSize: "11px", padding: "2px 8px", borderRadius: "10px", background: "rgba(255,255,255,0.08)", color: "#cbd5e1"}}>
                      {p.category}
                    </span>
                  )}
                  <span style={{fontSize: "11px", fontWeight: "bold", padding: "2px 8px", borderRadius: "10px", background: badgeBg, color: badgeColor}}>
                    {p.severity}
                  </span>
                </div>
              </div>
              <p style={{fontSize: "12px", color: "#cbd5e1", margin: "4px 0 6px 0", lineHeight: "1.5"}}>
                <strong>Rationale:</strong> {p.reason}
              </p>
              {p.attack_vector && (
                <div style={{fontSize: "11.5px", color: "#fca5a5", margin: "4px 0", background: "rgba(239, 68, 68, 0.06)", padding: "6px 8px", borderRadius: "4px"}}>
                  <strong>Threat Vector:</strong> {p.attack_vector}
                </div>
              )}
              {p.recommendation && (
                <div style={{fontSize: "11px", color: "var(--text-muted)", marginTop: "6px"}}>
                  <strong style={{color: "var(--neon-green)"}}>Mitigation:</strong> {p.recommendation}
                </div>
              )}
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
      const aiInsight = data.code_analysis?.ai_code_insight;
      return (
        <div>
          {aiInsight && (
            <div style={{
              marginBottom: "20px",
              padding: "16px 18px",
              borderRadius: "0",
              background: "rgba(0, 255, 36, 0.04)",
              border: "1px solid var(--neon-green)",
              boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.2)"
            }}>
              <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px", flexWrap: "wrap", gap: "8px"}}>
                <h4 style={{margin: 0, display: "flex", alignItems: "center", gap: "8px", color: "var(--neon-green)", fontSize: "14px", fontFamily: "var(--font-mono)", textTransform: "uppercase"}}>
                  <span>🤖</span> AI De-obfuscation & Deep Code Insight
                </h4>
                <span style={{fontSize: "11px", background: "#050505", border: "1px solid var(--neon-green)", color: "var(--neon-green)", padding: "2px 8px", borderRadius: "0", fontFamily: "monospace"}}>
                  qwen/qwen-2.5-coder-32b-instruct
                </span>
              </div>
              <div style={{fontSize: "12px", color: "#94a3b8", marginBottom: "8px"}}>
                <strong>Target Class:</strong> <span className="code-font" style={{color: "#e2e8f0"}}>{aiInsight.class_name}</span> (Line {aiInsight.line_number || "N/A"}) • <strong>Trigger API:</strong> <code style={{color: "#f43f5e"}}>{aiInsight.api}</code>
              </div>
              <div style={{fontSize: "13px", lineHeight: "1.6", color: "#e2e8f0", whiteSpace: "pre-line"}}>
                {aiInsight.explanation}
              </div>
            </div>
          )}

          <h4>Network Indicators</h4>
          <p>URLs: {data.code_analysis?.network_indicators?.urls?.length || 0} • IPs: {data.code_analysis?.network_indicators?.ipv4?.length || 0}</p>
          
          <h4>Suspicious APIs ({data.code_analysis?.suspicious_apis?.length || 0})</h4>
          <table className="results-table">
              <thead>
                <tr>
                  <th>Class & Line</th>
                  <th>API</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Evidence Rationale & Code Snippet</th>
                </tr>
              </thead>
              <tbody>
                  {(data.code_analysis?.suspicious_apis || []).map((api, i) => (
                      <tr key={i}>
                        <td>
                          <strong>{api.class_name}</strong>
                          {api.line_number && <div style={{fontSize: "11px", color: "#94a3b8"}}>Line {api.line_number}</div>}
                        </td>
                        <td className="code-font">{api.api}</td>
                        <td><span className="badge" style={{background: "rgba(255,255,255,0.08)", padding: "3px 6px"}}>{api.category || "General"}</span></td>
                        <td>
                          <span className={`badge ${api.severity === "High" ? "badge-danger" : (api.severity === "Medium" ? "badge-warning" : "badge-primary")}`}>
                            {api.severity}
                          </span>
                        </td>
                        <td style={{fontSize: "12px"}}>
                          {api.rationale && <div style={{color: "#cbd5e1", marginBottom: "4px"}}>{api.rationale}</div>}
                          {api.snippet && (
                            <pre className="code-font" style={{fontSize: "10.5px", margin: 0, padding: "4px 6px", background: "rgba(0,0,0,0.3)", borderRadius: "4px", whiteSpace: "pre-wrap"}}>
                              {api.snippet}
                            </pre>
                          )}
                        </td>
                      </tr>
                  ))}
              </tbody>
          </table>
          
          <h4>Malware Indicators ({data.code_analysis?.malware_indicators?.length || 0})</h4>
          <table className="results-table">
              <thead>
                <tr>
                  <th>Class & Line</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Forensic Reason</th>
                </tr>
              </thead>
              <tbody>
                {(data.code_analysis?.malware_indicators || []).map((ind, i) => (
                    <tr key={i}>
                      <td>
                        <strong>{ind.class_name}</strong>
                        {ind.line_number && <div style={{fontSize: "11px", color: "#94a3b8"}}>Line {ind.line_number}</div>}
                      </td>
                      <td><span className="badge" style={{background: "rgba(255,255,255,0.08)", padding: "3px 6px"}}>{ind.category || "Malware Indicator"}</span></td>
                      <td>
                        <span className={`badge ${ind.severity === "Critical" ? "badge-danger" : (ind.severity === "High" ? "badge-warning" : "badge-primary")}`}>
                          {ind.severity}
                        </span>
                      </td>
                      <td style={{fontSize: "12px", color: "#cbd5e1"}}>
                        <div>{ind.why_flagged}</div>
                        {ind.snippet && (
                          <pre className="code-font" style={{fontSize: "10.5px", marginTop: "4px", padding: "4px 6px", background: "rgba(0,0,0,0.3)", borderRadius: "4px", whiteSpace: "pre-wrap"}}>
                            {ind.snippet}
                          </pre>
                        )}
                      </td>
                    </tr>
                ))}
              </tbody>
          </table>
          
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
                              color: m.confidence_score >= 0.8 ? "var(--danger-red)" : (m.confidence_score >= 0.65 ? "var(--warning-amber)" : "var(--neon-green)")
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
                            {m.llm_explanation && (
                              <div style={{marginTop: "6px", padding: "8px", borderRadius: "6px", background: "rgba(124, 58, 237, 0.1)", border: "1px solid rgba(124, 58, 237, 0.3)"}}>
                                <div style={{fontSize: "10px", fontWeight: "bold", color: "#c084fc", marginBottom: "2px"}}>🤖 LLM Reverse-Engineering Insight (Qwen-2.5-Coder):</div>
                                <div style={{fontSize: "11px", color: "#e2e8f0", lineHeight: "1.4", whiteSpace: "pre-line"}}>{m.llm_explanation}</div>
                              </div>
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
             <div style={{fontSize: "48px", fontWeight: "bold", color: data.risk_analysis?.level === "Critical" ? "#ef4444" : (data.risk_analysis?.level === "High" ? "#f97316" : (data.risk_analysis?.level === "Medium" ? "#eab308" : "#22c55e"))}}>
                {data.risk_analysis?.score} / 100
             </div>
             <div style={{fontSize: "24px"}}>{data.risk_analysis?.level} Risk</div>
          </div>

          {data.risk_analysis?.executive_summary && (
            <div style={{
              marginTop: "16px",
              marginBottom: "24px",
              padding: "18px 20px",
              borderRadius: "0",
              background: "rgba(0, 255, 36, 0.04)",
              border: "1px solid var(--neon-green)",
              boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.3)"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "8px" }}>
                <h4 style={{ margin: 0, display: "flex", alignItems: "center", gap: "8px", color: "var(--neon-green)", fontSize: "15px", fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>
                  <span>🛡️</span> AI Threat Intelligence Executive Summary
                </h4>
                <span style={{ fontSize: "11px", background: "#050505", border: "1px solid var(--neon-green)", color: "var(--neon-green)", padding: "3px 10px", borderRadius: "0", fontFamily: "monospace" }}>
                  meta-llama/llama-3.3-70b-instruct
                </span>
              </div>
              <div style={{ fontSize: "13.5px", lineHeight: "1.7", color: "#e2e8f0", whiteSpace: "pre-line" }}>
                {data.risk_analysis.executive_summary}
              </div>
            </div>
          )}
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

    if (stageId === "dyn_prep") {
      return (
        <div>
          <h4>Android Emulator Sandbox Readiness</h4>
          <div className="metrics-grid">
            <div className="metric-box">
              <span className="metric-label">Sandbox Status</span>
              <span className="metric-value" style={{color: "#22c55e"}}>ONLINE</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">Target AVD</span>
              <span className="metric-value">{data.avd_name || "malware_sandbox"}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">Execution Mode</span>
              <span className="metric-value">{data.headless ? "Headless" : "GUI Window"}</span>
            </div>
          </div>
        </div>
      );
    }

    if (stageId === "dyn_deploy") {
      return (
        <div>
          <h4>Target Application Deployment</h4>
          <div className="metrics-grid">
            <div className="metric-box">
              <span className="metric-label">Package Name</span>
              <span className="metric-value code-font" style={{fontSize: "14px"}}>{data.package_name || "Unknown"}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">App State</span>
              <span className="metric-value" style={{color: "var(--neon-green)"}}>{data.status || "Running"}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">APK ID</span>
              <span className="metric-value code-font" style={{fontSize: "12px"}}>{data.apk_id}</span>
            </div>
          </div>
        </div>
      );
    }

    if (stageId === "dyn_monitor") {
      const net = data.dynamic_analysis?.network_traffic || [];
      const files = data.dynamic_analysis?.file_activity || [];
      const apis = data.dynamic_analysis?.api_calls || [];
      const sms = data.dynamic_analysis?.sms_interceptions || [];
      const procs = data.dynamic_analysis?.process_executions || [];
      const dexs = data.dynamic_analysis?.dynamic_dex_loads || [];
      const logcat = data.dynamic_analysis?.logcat_summary || {};

      return (
        <div>
          <h4>Dynamic Runtime Telemetry (Frida & mitmproxy)</h4>
          <div className="metrics-grid" style={{marginBottom: "20px"}}>
            <div className="metric-box">
              <span className="metric-label">Captured Connections</span>
              <span className="metric-value">{net.length}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">Sensitive API Calls</span>
              <span className="metric-value">{apis.length}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">File Operations</span>
              <span className="metric-value">{files.length}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">Critical Intercepts</span>
              <span className="metric-value" style={{color: (sms.length + procs.length + dexs.length) > 0 ? "#ef4444" : "#22c55e"}}>
                {sms.length + procs.length + dexs.length}
              </span>
            </div>
          </div>

          {/* High Priority Runtime Interceptions */}
          {sms.length > 0 && (
            <div style={{marginBottom: "16px", padding: "14px", borderRadius: "8px", background: "rgba(239, 68, 68, 0.1)", border: "1px solid #ef4444"}}>
              <h5 style={{color: "#f87171", margin: "0 0 8px 0"}}>⚠️ Intercepted Outbound SMS Transmission ({sms.length})</h5>
              {sms.map((s, i) => (
                <div key={i} style={{fontSize: "12px", marginBottom: "4px"}}>
                  <strong>Destination:</strong> <span className="code-font">{s.details?.destination || s.args?.[0]}</span> | <strong>Preview:</strong> <em>"{s.details?.snippet || s.args?.[1]}"</em>
                </div>
              ))}
            </div>
          )}

          {procs.length > 0 && (
            <div style={{marginBottom: "16px", padding: "14px", borderRadius: "8px", background: "rgba(249, 115, 22, 0.1)", border: "1px solid #f97316"}}>
              <h5 style={{color: "#fb923c", margin: "0 0 8px 0"}}>⚠️ System Process & Shell Execution ({procs.length})</h5>
              {procs.map((p, i) => (
                <div key={i} style={{fontSize: "12px", marginBottom: "4px"}}>
                  <strong>Command:</strong> <code className="code-font">{p.details?.command || (p.args || []).join(" ")}</code>
                </div>
              ))}
            </div>
          )}

          {dexs.length > 0 && (
            <div style={{marginBottom: "16px", padding: "14px", borderRadius: "0", background: "rgba(0, 255, 36, 0.06)", border: "1px solid var(--neon-green)"}}>
              <h5 style={{color: "var(--neon-green)", margin: "0 0 8px 0", fontFamily: "var(--font-mono)", textTransform: "uppercase"}}>⚠️ Dynamic DexClassLoader Invocations ({dexs.length})</h5>
              {dexs.map((d, i) => (
                <div key={i} style={{fontSize: "12px", marginBottom: "4px"}}>
                  <strong>Loaded Path:</strong> <code className="code-font">{d.details?.dexPath || d.args?.[0]}</code>
                </div>
              ))}
            </div>
          )}

          {net.length > 0 ? (
            <div>
              <h5>Intercepted Network Traffic</h5>
              <table className="results-table">
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Host</th>
                    <th>Path / URL</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {net.slice(0, 15).map((conn, i) => (
                    <tr key={i}>
                      <td><span className="badge badge-primary">{conn.method || "GET"}</span></td>
                      <td className="code-font">{conn.host || conn.destination_ip}</td>
                      <td className="code-font" style={{maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"}}>{conn.url || conn.path || "/"}</td>
                      <td>{conn.status_code || 200}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-muted">No outbound HTTP/HTTPS connections captured during observation window.</p>
          )}

          {apis.length > 0 && (
            <div style={{marginTop: "20px"}}>
              <h5>Sensitive API Invocations Hooked by Frida</h5>
              <table className="results-table">
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>API Hook</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {apis.slice(0, 10).map((call, i) => (
                    <tr key={i}>
                      <td><span className="badge badge-warning">{call.category || "API"}</span></td>
                      <td className="code-font">{call.method || call.api}</td>
                      <td>{call.details || JSON.stringify(call.args || {})}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Logcat Diagnostics */}
          {logcat && (logcat.crashes_detected > 0 || logcat.security_exceptions_count > 0 || logcat.permission_denials_count > 0) && (
            <div style={{marginTop: "20px", padding: "14px", borderRadius: "8px", background: "rgba(255, 255, 255, 0.03)", border: "1px solid #334155"}}>
              <h5 style={{margin: "0 0 10px 0"}}>Runtime Logcat Diagnostics</h5>
              <div style={{display: "flex", gap: "20px", fontSize: "13px", color: "#cbd5e1"}}>
                <div>Crashes: <strong style={{color: logcat.crashes_detected > 0 ? "#ef4444" : "#22c55e"}}>{logcat.crashes_detected}</strong></div>
                <div>Security Exceptions: <strong style={{color: logcat.security_exceptions_count > 0 ? "#f59e0b" : "#22c55e"}}>{logcat.security_exceptions_count}</strong></div>
                <div>Permission Denials: <strong style={{color: logcat.permission_denials_count > 0 ? "#f59e0b" : "#22c55e"}}>{logcat.permission_denials_count}</strong></div>
              </div>
            </div>
          )}
        </div>
      );
    }

    if (stageId === "dyn_c2") {
      const c2 = data.c2_detection || {};
      const hosts = data.suspected_c2_hosts || c2.suspected_c2_hosts || [];
      const indicators = c2.indicators || [];
      return (
        <div>
          <h4>Command & Control (C2) Detection Engine</h4>
          <div className="metrics-grid" style={{marginBottom: "20px"}}>
            <div className="metric-box">
              <span className="metric-label">C2 Heuristic Score</span>
              <span className="metric-value" style={{color: (c2.c2_heuristic_score || 0) >= 50 ? "#ef4444" : "#22c55e"}}>
                {c2.c2_heuristic_score ?? 0} / 100
              </span>
            </div>
            <div className="metric-box">
              <span className="metric-label">Suspected C2 Hosts</span>
              <span className="metric-value">{hosts.length}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">Indicators Flagged</span>
              <span className="metric-value">{indicators.length}</span>
            </div>
          </div>

          {hosts.length > 0 ? (
            <div>
              <h5>Suspected C2 Endpoints</h5>
              <table className="results-table">
                <thead>
                  <tr>
                    <th>Host / IP</th>
                    <th>Confidence</th>
                    <th>Forensic Indicators & Evidence</th>
                    <th>Reasons Flagged</th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.map((h, i) => (
                    <tr key={i}>
                      <td className="code-font"><strong>{h.host || h.ip || h}</strong></td>
                      <td>
                        <span className={`badge ${h.confidence === "high" ? "badge-danger" : (h.confidence === "medium" ? "badge-warning" : "badge-primary")}`}>
                          {h.confidence || "Medium"}
                        </span>
                      </td>
                      <td style={{fontSize: "12px"}}>
                        {h.evidence ? (
                          <div>
                            {h.evidence.requests_count !== undefined && (
                              <div><strong>Requests:</strong> {h.evidence.requests_count}</div>
                            )}
                            {h.evidence.ports && h.evidence.ports.length > 0 && (
                              <div><strong>Ports:</strong> {h.evidence.ports.join(", ")}</div>
                            )}
                            {h.evidence.beacon_interval_seconds && (
                              <div style={{color: "#f59e0b"}}><strong>Beacon Interval:</strong> ~{h.evidence.beacon_interval_seconds}s</div>
                            )}
                            {h.evidence.sample_paths && h.evidence.sample_paths.length > 0 && (
                              <div style={{color: "#94a3b8", fontSize: "11px", marginTop: "2px"}}>
                                <strong>Paths:</strong> {h.evidence.sample_paths.slice(0, 3).join(", ")}
                              </div>
                            )}
                            {h.evidence.status && (
                              <div style={{color: "#94a3b8", fontSize: "11px"}}>{h.evidence.status}</div>
                            )}
                          </div>
                        ) : (
                          <span className="text-muted">Dynamic Telemetry</span>
                        )}
                      </td>
                      <td style={{fontSize: "12px", color: "#cbd5e1"}}>{(h.reasons || []).join("; ") || "Beaconing / Suspicious Endpoint"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-muted">No high-confidence C2 communication channels detected.</p>
          )}

          {/* DGA Domains Alert */}
          {((data.dga_detections && data.dga_detections.length > 0) || (c2.dga_detections && c2.dga_detections.length > 0)) && (
            <div style={{marginBottom: "20px", padding: "14px", borderRadius: "8px", background: "rgba(239, 68, 68, 0.12)", border: "1px solid #ef4444"}}>
              <h5 style={{color: "#f87171", margin: "0 0 8px 0"}}>🚨 Algorithmically Generated Domains (DGA) Detected</h5>
              <table className="results-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Entropy</th>
                    <th>Vowel Ratio</th>
                    <th>Heuristic Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.dga_detections || c2.dga_detections).map((d, i) => (
                    <tr key={i}>
                      <td className="code-font" style={{color: "#fca5a5"}}>{d.domain}</td>
                      <td>{d.entropy} bits/sym</td>
                      <td>{d.vowel_ratio}</td>
                      <td style={{fontSize: "12px", color: "#fca5a5"}}>{(d.reasons || []).join("; ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {indicators.length > 0 && (
            <div style={{marginTop: "20px"}}>
              <h5>Behavioral C2 Indicators</h5>
              <ul>
                {indicators.map((ind, i) => (
                  <li key={i} style={{marginBottom: "8px"}}>
                    <strong>{ind.indicator}</strong> ({ind.severity}): {ind.description}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      );
    }

    if (stageId === "dyn_reputation") {
      const rep = data.server_reputation || {};
      const checked = data.checked || rep.checked || [];
      return (
        <div>
          <h4>External Threat Intelligence (AbuseIPDB & VirusTotal)</h4>
          <p className="text-muted" style={{fontSize: "13px"}}>
            Cross-references contacted servers and IPs against live cybersecurity threat databases.
          </p>
          {checked.length > 0 ? (
            <table className="results-table">
              <thead>
                <tr>
                  <th>Target Server</th>
                  <th>Abuse Score</th>
                  <th>VirusTotal Positives</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {checked.map((s, i) => (
                  <tr key={i}>
                    <td className="code-font">{s.host || s.ip}</td>
                    <td>{s.abuse_score ?? "N/A"}%</td>
                    <td>{s.vt_positives ?? "N/A"}</td>
                    <td>
                      <span className={`badge ${s.verdict === "malicious" ? "badge-danger" : (s.verdict === "suspicious" ? "badge-warning" : "badge-success")}`}>
                        {s.verdict || "Clean"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-muted">No external hosts required reputation validation, or queries completed cleanly.</p>
          )}
        </div>
      );
    }

    if (stageId === "dyn_report") {
      const risk = data.risk_assessment || {};
      const confirmed = data.confirmed_threats || [];
      const narrative = data.unified_threat_narrative;

      return (
        <div>
          <h4>Unified Risk Correlation & Forensic Reports</h4>
          <div style={{display: "flex", alignItems: "center", gap: "20px", marginBottom: "20px"}}>
            <div style={{fontSize: "48px", fontWeight: "bold", color: (risk.risk_score || 0) >= 50 ? "#ef4444" : "#22c55e"}}>
              {risk.risk_score ?? 0} / 100
            </div>
            <div>
              <div style={{fontSize: "24px", fontWeight: "700"}}>{risk.risk_label || "Low Risk"}</div>
              <p className="text-muted" style={{margin: "4px 0 0 0", fontSize: "13px"}}>Package: {data.package_name || "Analyzed APK"}</p>
            </div>
          </div>

          {/* Confirmed Multi-Vector Correlated Threats */}
          {confirmed.length > 0 && (
            <div style={{marginBottom: "20px", padding: "16px", borderRadius: "0", background: "rgba(239, 68, 68, 0.12)", border: "1px solid #ef4444"}}>
              <h5 style={{color: "#f87171", margin: "0 0 8px 0", fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.5px"}}>🚨 Confirmed Multi-Vector Threats (Static Intent + Runtime Reality)</h5>
              <ul style={{margin: 0, paddingLeft: "20px", color: "#fca5a5", fontSize: "13px"}}>
                {confirmed.map((ct, i) => (
                  <li key={i} style={{marginBottom: "4px"}}><strong>{ct}</strong></li>
                ))}
              </ul>
            </div>
          )}

          {/* Unified LLM Narrative */}
          {narrative && !narrative.startsWith("[") && (
            <div style={{marginBottom: "20px", padding: "18px 20px", borderRadius: "0", background: "rgba(0, 255, 36, 0.05)", border: "1px solid var(--neon-green)"}}>
              <h5 style={{color: "var(--neon-green)", margin: "0 0 10px 0", fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "1px"}}>🧠 Executive Forensic Threat Narrative (OpenRouter LLaMA-3.3-70B)</h5>
              <div style={{fontSize: "13.5px", lineHeight: "1.7", color: "var(--text-main)", whiteSpace: "pre-line"}}>
                {narrative}
              </div>
            </div>
          )}

          <h5>Contributing Threat Factors</h5>
          <ul>
            {(risk.contributing_factors || []).map((f, i) => <li key={i}>{f}</li>)}
          </ul>

          <div style={{marginTop: "25px", display: "flex", gap: "12px", flexWrap: "wrap"}}>
            <a
              href={`http://localhost:8000/api/report/view/${data.apk_id}`}
              target="_blank"
              rel="noreferrer"
              className="btn btn-primary"
            >
              📄 View Interactive HTML Report
            </a>
            <a
              href={`http://localhost:8000/api/report/download/${data.apk_id}?format=pdf`}
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
            >
              📥 Download PDF Report
            </a>
            <a
              href={`http://localhost:8000/api/report/download/${data.apk_id}?format=json`}
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
            >
              📊 Download JSON Telemetry
            </a>
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
