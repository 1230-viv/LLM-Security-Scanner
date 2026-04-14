import { Link } from "react-router-dom";

import type { ScanHistoryItem } from "@/types";

interface Props {
  scans: ScanHistoryItem[];
}

function ScanHistory({ scans }: Props): JSX.Element {
  return (
    <section className="card-surface p-5 sm:p-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h2 className="card-heading">Recent Scans</h2>
        <span className="rounded-full border border-slate-300 bg-slate-50 px-3 py-1 text-xs font-semibold text-slate-600">
          {scans.length} records
        </span>
      </div>

      {scans.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-6 text-sm text-slate-600">
          No scans yet. Start a new run to populate this history.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-200">
          <table className="min-w-full divide-y divide-slate-200 bg-white text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-[0.08em] text-slate-600">
              <tr>
                <th className="px-4 py-3 text-left">Timestamp</th>
                <th className="px-4 py-3 text-left">Target</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Findings</th>
                <th className="px-4 py-3 text-left">Open</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {scans.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-slate-50/80">
                  <td className="px-4 py-3">{new Date(scan.created_at).toLocaleString()}</td>
                  <td className="max-w-sm truncate px-4 py-3">{scan.target_endpoint}</td>
                  <td className="px-4 py-3">
                    <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700">
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-semibold text-slate-900">{scan.vulnerability_count}</td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/scan/${scan.scan_id}`}
                      className="font-semibold text-slate-800 underline decoration-slate-300 underline-offset-4 hover:text-slate-950"
                    >
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default ScanHistory;
