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

  const statusTone =
    status.status === "completed"
      ? "bg-emerald-100 text-emerald-800"
      : status.status === "failed"
        ? "bg-red-100 text-red-800"
        : "bg-amber-100 text-amber-800";

  return (
    <section className="card-surface p-5 sm:p-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="card-heading">Scan Status</h2>
        <span className={`rounded-full px-3 py-1 text-xs font-bold uppercase tracking-[0.08em] ${statusTone}`}>
          {status.status}
        </span>
      </div>

      <div className="h-3.5 w-full overflow-hidden rounded-full bg-slate-200" role="progressbar" aria-valuenow={progress}>
        <div
          className="h-full animate-pulsebar rounded-full bg-gradient-to-r from-slate-900 via-slate-700 to-emerald-500 transition-all duration-300"
          style={{ width: `${progress}%` }}
        />
      </div>

      <p className="mt-3 text-sm text-slate-700">
        {status.progress.completed_prompts} / {status.progress.total_prompts} prompts completed
      </p>

      {status.error_message ? (
        <p className="mt-3 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {status.error_message}
        </p>
      ) : null}

      {report ? (
        <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-xl border border-slate-200 bg-white p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">Total Findings</p>
            <strong className="mt-1 block text-2xl font-display text-slate-950">{report.summary.total_vulnerabilities}</strong>
          </div>
          <div className="rounded-xl border border-red-200 bg-red-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-red-600">High Severity</p>
            <strong className="mt-1 block text-2xl font-display text-red-700">{report.summary.high_severity}</strong>
          </div>
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-amber-700">Medium Severity</p>
            <strong className="mt-1 block text-2xl font-display text-amber-700">{report.summary.medium_severity}</strong>
          </div>
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-emerald-700">Low Severity</p>
            <strong className="mt-1 block text-2xl font-display text-emerald-700">{report.summary.low_severity}</strong>
          </div>
        </div>
      ) : null}
    </section>
  );
}

export default ScanStatus;
