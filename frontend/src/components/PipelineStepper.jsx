import React from "react";

export default function PipelineStepper({
  stages,
  currentStageIndex,
  onSelectStage,
  onRunNextStage,
  onRunAllRemaining,
  isRunning,
  hasApk,
}) {
  return (
    <div className="card stepper-card">
      <div className="card-header">
        <h2 className="card-title">Analysis Pipeline Lifecycle</h2>
        <div className="stepper-actions">
          <button
            className="btn btn-secondary btn-sm"
            disabled={!hasApk || isRunning}
            onClick={onRunNextStage}
          >
            {isRunning ? "Running Stage..." : "Run Next Stage →"}
          </button>
          <button
            className="btn btn-accent btn-sm"
            disabled={!hasApk || isRunning}
            onClick={onRunAllRemaining}
          >
            ⚡ Run All Remaining
          </button>
        </div>
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
              onClick={() => onSelectStage(index)}
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
