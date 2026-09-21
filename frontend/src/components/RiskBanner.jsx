import React from "react";

export default function RiskBanner({ correlationData }) {
  if (!correlationData || !correlationData.risk_assessment) {
    return null;
  }

  const { risk_score, risk_label, contributing_factors, score_breakdown } =
    correlationData.risk_assessment;

  let bannerClass = "low";
  if (risk_score > 75) bannerClass = "critical";
  else if (risk_score > 50) bannerClass = "high";
  else if (risk_score > 25) bannerClass = "medium";

  return (
    <div className="risk-container">
      <div className={`risk-banner risk-banner-${bannerClass}`}>
        <div className="risk-banner-content">
          <h2 className="risk-label-title">{risk_label}</h2>
          <p className="risk-subtitle">Unified Multi-Stage Threat Evaluation</p>
        </div>
        <div className="risk-banner-score">
          <span className="score-num">{risk_score}</span>
          <span className="score-denom">/ 100</span>
        </div>
      </div>

      <div className="card risk-details-card">
        <h3 className="section-heading">Key Threat Contributing Factors</h3>
        <ul className="factors-list">
          {contributing_factors && contributing_factors.length > 0 ? (
            contributing_factors.map((factor, idx) => (
              <li key={idx} className="factor-item">
                <span className="factor-bullet">•</span> {factor}
              </li>
            ))
          ) : (
            <li className="text-muted">No significant risk indicators reported.</li>
          )}
        </ul>

        {score_breakdown && (
          <div className="breakdown-grid">
            <div className="breakdown-item">
              <span className="breakdown-label">Permissions</span>
              <span className="breakdown-score">+{score_breakdown.dangerous_permissions_score}</span>
            </div>
            <div className="breakdown-item">
              <span className="breakdown-label">YARA Signatures</span>
              <span className="breakdown-score">+{score_breakdown.yara_matches_score}</span>
            </div>
            <div className="breakdown-item">
              <span className="breakdown-label">VirusTotal</span>
              <span className="breakdown-score">+{score_breakdown.virustotal_score}</span>
            </div>
            <div className="breakdown-item">
              <span className="breakdown-label">DEX Code APIs</span>
              <span className="breakdown-score">+{score_breakdown.suspicious_apis_score}</span>
            </div>
            <div className="breakdown-item">
              <span className="breakdown-label">C2 Detection</span>
              <span className="breakdown-score">+{score_breakdown.c2_hosts_score}</span>
            </div>
            <div className="breakdown-item">
              <span className="breakdown-label">Server Reputation</span>
              <span className="breakdown-score">+{score_breakdown.server_reputation_score}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
