import type { ReportResponse, ScanStatusResponse } from "@/types";

interface Props {
  status: ScanStatusResponse;
  report?: ReportResponse;
}

function ScanStatus({ status, report }: Props): JSX.Element {
  const total = status.progress.total_prompts || 1;
  const progress = Math.min(
    100,
    Math.round((status.progress.completed_prompts / total) * 100),
  );

  return (
    <section className="panel">
      <div className="inline-row">
        <h2>Scan Status</h2>
        <strong>{status.status.toUpperCase()}</strong>
      </div>

      <div className="progress-shell" role="progressbar" aria-valuenow={progress}>
        <div className="progress-bar" style={{ width: `${progress}%` }} />
      </div>

      <p>
        {status.progress.completed_prompts} / {status.progress.total_prompts} prompts completed
      </p>

      {status.error_message ? <p className="error-text">{status.error_message}</p> : null}

      {report ? (
        <div className="stat-grid">
          <div className="stat-card">
            <p>Total Findings</p>
            <strong>{report.summary.total_vulnerabilities}</strong>
          </div>
          <div className="stat-card">
            <p>High Severity</p>
            <strong>{report.summary.high_severity}</strong>
          </div>
          <div className="stat-card">
            <p>Medium Severity</p>
            <strong>{report.summary.medium_severity}</strong>
          </div>
          <div className="stat-card">
            <p>Low Severity</p>
            <strong>{report.summary.low_severity}</strong>
          </div>
        </div>
      ) : null}
    </section>
  );
}

export default ScanStatus;
