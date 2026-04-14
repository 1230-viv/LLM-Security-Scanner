import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { getMarkdownReport } from "@/services/api";

function ReportPage(): JSX.Element {
  const { scanId = "" } = useParams();
  const [content, setContent] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [copied, setCopied] = useState(false);

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

  const handleCopy = async (): Promise<void> => {
    if (!content) {
      return;
    }

    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setError("Unable to copy report to clipboard");
    }
  };

  return (
    <section className="card-surface p-5 sm:p-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3">
        <div>
          <h2 className="card-heading">Markdown Report</h2>
          <p className="mt-1 text-sm text-slate-600">Scan ID: {scanId}</p>
        </div>

        <button
          type="button"
          onClick={handleCopy}
          className="rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-800 transition hover:border-slate-500"
        >
          {copied ? "Copied" : "Copy Markdown"}
        </button>
      </div>

      {error ? (
        <p className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
      ) : (
        <pre className="code-scroll max-h-[70vh] overflow-auto rounded-xl border border-slate-200 bg-slate-950 p-4 font-mono text-xs leading-6 text-slate-100">
          {content || "Loading report..."}
        </pre>
      )}
    </section>
  );
}

export default ReportPage;
