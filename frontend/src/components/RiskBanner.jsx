import React from "react";

export default function RiskBanner({ correlationData }) {
  if (!correlationData) {
    return null;
  }

  const score = correlationData.overall ?? correlationData.score ?? correlationData.risk_score ?? 0;
  const level = correlationData.level || correlationData.threat_level || correlationData.risk_label || "Low";
  const factors = correlationData.top_reasons || correlationData.factors || [];
  const recommendations = correlationData.recommendations || [];
  const publisherVerified = correlationData.publisher_verified;

  const numScore = Number(score);
  let bannerClass = "low";
  if (numScore >= 75) bannerClass = "critical";
  else if (numScore >= 50) bannerClass = "high";
  else if (numScore >= 25) bannerClass = "medium";

  return (
    <div className="risk-container">
      <div className={`risk-banner risk-banner-${bannerClass}`}>
        <div className="risk-banner-content">
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <h2 className="risk-label-title">{level} Risk</h2>
            {publisherVerified && (
              <span style={{ fontSize: "12px", background: "rgba(0,255,36,0.15)", color: "#00ff24", border: "1px solid #00ff24", padding: "2px 8px", borderRadius: "4px" }}>
                [VERIFIED PUBLISHER]
              </span>
            )}
          </div>
          <p className="risk-subtitle">Static Threat Analysis Engine v2</p>
        </div>
        <div className="risk-banner-score">
          <span className="score-num">{numScore.toFixed(1)}</span>
          <span className="score-denom">/ 100</span>
        </div>
      </div>

      <div className="card risk-details-card" style={{ marginTop: "20px" }}>
        <h3 className="section-heading">Key Threat Contributing Factors</h3>
        <ul className="factors-list">
          {factors && factors.length > 0 ? (
            factors.map((factor, idx) => (
              <li key={idx} className="factor-item">
                <span className="factor-bullet">-</span> {factor}
              </li>
            ))
          ) : (
            <li className="text-muted">No significant risk indicators reported.</li>
          )}
        </ul>

        <h3 className="section-heading" style={{ marginTop: "20px" }}>Security Recommendations</h3>
        <ul className="factors-list">
          {recommendations && recommendations.length > 0 ? (
            recommendations.map((rec, idx) => (
              <li key={idx} className="factor-item">
                <span className="factor-bullet">[OK]</span> {rec}
              </li>
            ))
          ) : (
            <li className="text-muted">No specific recommendations.</li>
          )}
        </ul>
      </div>
    </div>
  );
}
