import { useEffect, useState } from "react";

import ScanHistory from "@/components/ScanHistory";
import { getHistory } from "@/services/api";
import type { ScanHistoryItem } from "@/types";

function HistoryPage(): JSX.Element {
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    const loadHistory = async (): Promise<void> => {
      try {
        const result = await getHistory(50);
        setScans(result);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Unable to load history");
      }
    };

    loadHistory();
  }, []);

  return (
    <>
      <section className="card-surface p-5 sm:p-6">
        <h2 className="card-heading">Historical Runs</h2>
        <p className="mt-2 text-sm text-slate-600">
          Review completed and in-progress scans, then reopen any run to inspect details and
          export reports.
        </p>
      </section>

      {error ? (
        <p className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {error}
        </p>
      ) : null}
      <ScanHistory scans={scans} />
    </>
  );
}

export default HistoryPage;
