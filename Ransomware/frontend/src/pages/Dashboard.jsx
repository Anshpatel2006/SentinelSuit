import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getHealth, listReports } from "../api/client";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import RiskBadge from "../components/ui/RiskBadge";
import StatCard from "../components/ui/StatCard";

export default function Dashboard() {
  const [reports, setReports] = useState([]);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([getHealth(), listReports()])
      .then(([h, r]) => {
        setHealth({ cape: h.cape_available });
        setReports(r);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load dashboard"));
  }, []);

  return (
    <div>
      <PageHeader
        title="Analysis Dashboard"
        subtitle="Recent reports and system status"
        action={
          <Link to="/upload" className="btn btn-primary">
            + New Analysis
          </Link>
        }
      />

      {error && <Alert>{error}</Alert>}

      {health && (
        <div className="stats-grid">
          <StatCard
            label="CAPE Sandbox"
            value={health.cape ? "Online" : "Offline"}
            valueClass={health.cape ? "text-ok" : "text-warn"}
          />
          <StatCard label="Total Reports" value={reports.length} />
        </div>
      )}

      <section className="panel">
        <h2>Recent Reports</h2>
        {reports.length === 0 ? (
          <p className="muted">No reports yet. Upload a sample to begin analysis.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Sample ID</th>
                <th>Filename</th>
                <th>Branch</th>
                <th>Risk</th>
                <th>SHA256</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.sample_id}>
                  <td className="mono">{r.sample_id}</td>
                  <td>{r.filename}</td>
                  <td>{r.branch || "—"}</td>
                  <td>
                    <RiskBadge level={r.risk_level} score={r.risk_score} />
                  </td>
                  <td className="mono truncate">{r.sha256?.slice(0, 16)}…</td>
                  <td>
                    <Link to={`/reports/${r.sample_id}`} className="btn btn-sm">
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
