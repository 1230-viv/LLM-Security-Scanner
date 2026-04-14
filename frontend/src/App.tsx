import { NavLink, Navigate, Route, Routes } from "react-router-dom";

import HomePage from "@/pages/HomePage";
import HistoryPage from "@/pages/HistoryPage";
import ReportPage from "@/pages/ReportPage";
import ScanPage from "@/pages/ScanPage";

function App(): JSX.Element {
  return (
    <div className="mx-auto min-h-screen w-full max-w-7xl px-4 pb-10 pt-5 sm:px-6 lg:px-8">
      <header className="card-surface animate-fade-up p-4 sm:p-6">
        <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
          <div className="flex items-center gap-4">
            <span
              aria-hidden
              className="grid h-12 w-12 place-items-center rounded-xl bg-gradient-to-br from-slate-700 to-emerald-500 font-display text-lg font-bold text-white"
            >
              LS
            </span>
            <div>
              <p className="font-display text-2xl font-semibold tracking-tight text-slate-950">
                LLM Security Scanner Lab
              </p>
              <p className="mt-1 text-sm text-slate-600">
                Tailwind-powered testing console for backend red-team scans
              </p>
            </div>
          </div>

          <nav className="flex items-center gap-2 rounded-full border border-slate-300/80 bg-white/80 p-1.5">
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                `rounded-full px-4 py-2 text-sm font-semibold transition ${
                  isActive
                    ? "bg-slate-900 text-white"
                    : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                }`
              }
            >
              New Scan
            </NavLink>
            <NavLink
              to="/history"
              className={({ isActive }) =>
                `rounded-full px-4 py-2 text-sm font-semibold transition ${
                  isActive
                    ? "bg-slate-900 text-white"
                    : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                }`
              }
            >
              Scan History
            </NavLink>
          </nav>
        </div>
      </header>

      <main className="mt-6 space-y-6 animate-fade-up [animation-delay:100ms]">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/scan/:scanId" element={<ScanPage />} />
          <Route path="/report/:scanId" element={<ReportPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
