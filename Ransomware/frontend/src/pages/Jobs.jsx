import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listJobs } from "../api/client";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";

export default function Jobs() {
  const [jobs, setJobs] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const load = () =>
      listJobs()
        .then(setJobs)
        .catch((e) => setError(e instanceof Error ? e.message : "Failed to load jobs"));

    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <PageHeader
        title="Active Jobs"
        subtitle="Background analysis tasks submitted via the API"
        action={
          <Link to="/upload" className="btn btn-primary">
            + New Analysis
          </Link>
        }
      />

      {error && <Alert>{error}</Alert>}

      <section className="panel">
        {jobs.length === 0 ? (
          <p className="muted">No jobs yet. Upload a sample to start an analysis.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Filename</th>
                <th>Status</th>
                <th>Current stage</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.job_id}>
                  <td className="mono">{job.job_id.slice(0, 12)}…</td>
                  <td>{job.filename}</td>
                  <td>
                    <span className={`badge badge-${job.status}`}>{job.status}</span>
                  </td>
                  <td>{job.current_stage || "Processing analysis"}</td>
                  <td className="mono">{new Date(job.created_at).toLocaleString()}</td>
                  <td>
                    {job.status === "completed" && job.sample_id && (
                      <Link to={`/reports/${job.sample_id}`} className="btn btn-sm">
                        View Report
                      </Link>
                    )}
                    {job.status === "failed" && <span className="text-danger">{job.error}</span>}
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
