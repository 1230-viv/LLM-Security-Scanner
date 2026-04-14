import { useNavigate } from "react-router-dom";

import ScanForm from "@/components/ScanForm";

function HomePage(): JSX.Element {
  const navigate = useNavigate();

  return (
    <>
      <section className="card-surface grid gap-4 p-5 sm:grid-cols-3 sm:p-6">
        <div className="sm:col-span-2">
          <h2 className="card-heading">Ollama Endpoint Security Testbench</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
            Configure your Ollama API endpoint, tune attack categories, and launch asynchronous scan
            runs against your backend. This UI is purpose-built for rapid prompt-security testing in
            local or remote model deployments.
          </p>
        </div>

        <div className="grid gap-2 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
          <p className="font-display text-base font-semibold text-slate-900">Quick Targets</p>
          <span className="tag-chip">http://localhost:11434/api/generate</span>
          <span className="tag-chip">http://localhost:11434/api/chat</span>
          <span className="tag-chip">OpenAI-compatible gateway</span>
        </div>
      </section>
      <ScanForm onScanCreated={(scanId) => navigate(`/scan/${scanId}`)} />
    </>
  );
}

export default HomePage;
