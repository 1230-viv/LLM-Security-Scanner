import { Link, Navigate, Route, Routes } from "react-router-dom";

import HomePage from "@/pages/HomePage";
import HistoryPage from "@/pages/HistoryPage";
import ReportPage from "@/pages/ReportPage";
import ScanPage from "@/pages/ScanPage";

function App(): JSX.Element {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <span className="brand-mark" aria-hidden>
            LSS
          </span>
          <div>
            <h1>LLM Security Scanner</h1>
            <p>Production red-teaming dashboard</p>
          </div>
        </div>

        <nav className="nav-links">
          <Link to="/">New Scan</Link>
          <Link to="/history">Scan History</Link>
        </nav>
      </header>

      <main className="content-container">
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
