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
      <section className="panel inline-row">
        <div>
          <h2>Scan Session</h2>
          <p>Scan ID: {scanId}</p>
        </div>
        <Link to={`/report/${scanId}`}>Open Markdown Report</Link>
      </section>

      {error ? <p className="error-text">{error}</p> : null}

      {status ? <ScanStatus status={status} report={report} /> : <section className="panel">Loading...</section>}

      {hasFindings && report ? (
        <div className="grid-2">
          <VulnerabilityList
            vulnerabilities={report.vulnerabilities}
            selectedId={selected?.id}
            onSelect={setSelected}
          />
          <VulnerabilityDetail vulnerability={selected} />
        </div>
      ) : (
        <section className="panel">
          {status?.status === "completed"
            ? "No vulnerabilities were detected in this run."
            : "Findings will appear when the scan completes."}
        </section>
      )}
    </>
  );
}

export default ScanPage;
