import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import ScanStatus from "@/components/ScanStatus";
import VulnerabilityDetail from "@/components/VulnerabilityDetail";
import VulnerabilityList from "@/components/VulnerabilityList";
import { getReport, getScanStatus } from "@/services/api";
import type { ReportResponse, ReportVulnerability, ScanStatusResponse } from "@/types";

function ScanPage(): JSX.Element {
  const { scanId = "" } = useParams();
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [report, setReport] = useState<ReportResponse | undefined>();
  const [selected, setSelected] = useState<ReportVulnerability | undefined>();
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let timer: number | undefined;

    const poll = async (): Promise<void> => {
      try {
        const nextStatus = await getScanStatus(scanId);
        setStatus(nextStatus);

        if (nextStatus.status === "completed") {
          const completedReport = await getReport(scanId);
          setReport(completedReport);
          setSelected((previous) =>
            previous
              ? completedReport.vulnerabilities.find((item) => item.id === previous.id)
              : completedReport.vulnerabilities[0],
          );
          return;
        }

        if (nextStatus.status === "failed") {
          return;
        }

        timer = window.setTimeout(poll, 2000);
      } catch (pollError) {
        setError(pollError instanceof Error ? pollError.message : "Failed to load scan status");
      }
    };

    poll();

    return () => {
      if (timer) {
        window.clearTimeout(timer);
      }
    };
  }, [scanId]);

  const hasFindings = useMemo(() => (report?.vulnerabilities.length ?? 0) > 0, [report]);

  return (
    <>
      <section className="card-surface flex flex-col justify-between gap-4 p-5 sm:flex-row sm:items-center sm:p-6">
        <div>
          <h2 className="card-heading">Scan Session</h2>
          <p className="mt-1 break-all font-mono text-xs text-slate-600">Scan ID: {scanId}</p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to={`/report/${scanId}`}
            className="rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-800 transition hover:border-slate-500"
          >
            Open Markdown Report
          </Link>
          <Link
            to="/"
            className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-slate-800"
          >
            New Scan
          </Link>
        </div>
      </section>

      {error ? (
        <p className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {error}
        </p>
      ) : null}

      {status ? (
        <ScanStatus status={status} report={report} />
      ) : (
        <section className="card-surface p-5 text-sm text-slate-600">Loading status...</section>
      )}

      {hasFindings && report ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <VulnerabilityList
            vulnerabilities={report.vulnerabilities}
            selectedId={selected?.id}
            onSelect={setSelected}
          />
          <VulnerabilityDetail vulnerability={selected} />
        </div>
      ) : (
        <section className="card-surface p-5 text-sm text-slate-600">
          {status?.status === "completed"
            ? "No vulnerabilities were detected in this run."
            : "Findings will appear when the scan completes."}
        </section>
      )}
    </>
  );
}

export default ScanPage;
