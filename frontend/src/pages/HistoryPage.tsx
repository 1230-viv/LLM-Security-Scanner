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
      {error ? <p className="error-text">{error}</p> : null}
      <ScanHistory scans={scans} />
    </>
  );
}

export default HistoryPage;
