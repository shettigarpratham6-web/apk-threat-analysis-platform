import React from "react";

export default function RiskBanner({ correlationData }) {
  if (!correlationData) {
    return null;
  }

  const { score, level, factors, recommendations } = correlationData;

  let bannerClass = "low";
  if (score >= 80) bannerClass = "critical";
  else if (score >= 60) bannerClass = "high";
  else if (score >= 40) bannerClass = "medium";

  return (
    <div className="risk-container">
      <div className={`risk-banner risk-banner-${bannerClass}`}>
        <div className="risk-banner-content">
          <h2 className="risk-label-title">{level} Risk</h2>
          <p className="risk-subtitle">Static Threat Correlation Engine</p>
        </div>
        <div className="risk-banner-score">
          <span className="score-num">{score}</span>
          <span className="score-denom">/ 100</span>
        </div>
      </div>

      <div className="card risk-details-card" style={{ marginTop: "20px" }}>
        <h3 className="section-heading">Key Threat Contributing Factors</h3>
        <ul className="factors-list">
          {factors && factors.length > 0 ? (
            factors.map((factor, idx) => (
              <li key={idx} className="factor-item">
                <span className="factor-bullet">•</span> {factor}
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
                <span className="factor-bullet">✅</span> {rec}
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
