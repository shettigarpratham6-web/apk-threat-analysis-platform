import React from "react";

export default function PipelineStepper({
  stages,
  currentStageIndex,
  onSelectStage,
  isRunning,
  hasApk,
}) {
  return (
    <div className="card stepper-card">
      <div className="card-header">
        <h2 className="card-title">Static Analysis Lifecycle</h2>
      </div>

      <div className="stepper-list">
        {stages.map((stage, index) => {
          let statusClass = "pending";
          if (stage.status === "completed") statusClass = "completed";
          else if (stage.status === "running") statusClass = "running";
          else if (stage.status === "error") statusClass = "error";

          const isSelected = index === currentStageIndex;

          return (
            <div
              key={stage.id}
              className={`stepper-item ${statusClass} ${isSelected ? "selected" : ""}`}
              onClick={() => {
                 if(hasApk && stage.status === "completed") {
                     onSelectStage(index);
                 }
              }}
              style={{ cursor: (hasApk && stage.status === "completed") ? "pointer" : "default" }}
            >
              <div className="stepper-icon">
                {stage.status === "completed" ? "✓" : stage.status === "running" ? "⏳" : stage.status === "error" ? "✕" : index + 1}
              </div>
              <div className="stepper-content">
                <div className="stepper-title">{stage.title}</div>
                <div className="stepper-subtitle">{stage.subtitle}</div>
              </div>
              <div className="stepper-status-badge">{stage.status}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
