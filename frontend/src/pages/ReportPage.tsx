import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { getMarkdownReport } from "@/services/api";

function ReportPage(): JSX.Element {
  const { scanId = "" } = useParams();
  const [content, setContent] = useState<string>("");
  const [error, setError] = useState<string>("");

  useEffect(() => {
    const loadReport = async (): Promise<void> => {
      try {
        const markdown = await getMarkdownReport(scanId);
        setContent(markdown);
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Unable to load report");
      }
    };

    loadReport();
  }, [scanId]);

  return (
    <section className="panel">
      <h2>Markdown Report</h2>
      {error ? <p className="error-text">{error}</p> : <pre className="code-block">{content}</pre>}
    </section>
  );
}

export default ReportPage;
