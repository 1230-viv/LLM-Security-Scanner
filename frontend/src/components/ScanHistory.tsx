import { Link } from "react-router-dom";

import type { ScanHistoryItem } from "@/types";

interface Props {
  scans: ScanHistoryItem[];
}

function ScanHistory({ scans }: Props): JSX.Element {
  return (
    <section className="panel">
      <h2>Recent Scans</h2>
      <table className="table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Target</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Open</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.scan_id}>
              <td>{new Date(scan.created_at).toLocaleString()}</td>
              <td>{scan.target_endpoint}</td>
              <td>{scan.status}</td>
              <td>{scan.vulnerability_count}</td>
              <td>
                <Link to={`/scan/${scan.scan_id}`}>View</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {scans.length === 0 ? <p>No scans yet.</p> : null}
    </section>
  );
}

export default ScanHistory;
