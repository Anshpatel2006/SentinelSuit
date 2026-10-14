import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { downloadReportPdf, getReport } from "../api/client";
import Alert from "../components/ui/Alert";

export default function ReportDetail() {
  const { sampleId } = useParams();
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");

  const handleDownloadPdf = async () => {
    if (!sampleId) return;
    try {
      const blob = await downloadReportPdf(sampleId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${sampleId}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to download PDF report");
    }
  };

  const handleDownloadJson = () => {
    if (!report || !sampleId) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${sampleId}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  useEffect(() => {
    if (!sampleId) return;
    getReport(sampleId)
      .then(setReport)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load report"));
  }, [sampleId]);

  if (error) return <Alert>{error}</Alert>;
  if (!report) return <p className="muted">Loading report…</p>;

  const meta = report.metadata;
  const hashes = report.hashes;
  const risk = report.risk;
  const ml = report.ml;
  const iocs = report.iocs;
  const cape = report.cape;
  const capeStatus = cape?.status || cape?.task?.status || (cape?.statistics ? "reported" : "not_available");

  return (
    <div>
      <header className="page-header">
        <div>
          <Link to="/" className="back-link">
            ← Dashboard
          </Link>
          <h1>{String(meta?.original_name || sampleId)}</h1>
          <p className="mono muted">{sampleId}</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap", justifyContent: "flex-end" }}>
          <div className="report-actions">
            <button type="button" className="btn" onClick={handleDownloadJson}>
              Download JSON
            </button>
            <button type="button" className="btn btn-primary" onClick={handleDownloadPdf}>
              Download PDF
            </button>
          </div>
          {risk && (
            <div className={`risk-banner risk-${risk.level}`}>
              <div className="risk-level">{risk.level?.toUpperCase()}</div>
              <div className="risk-score">{risk.score}/100</div>
            </div>
          )}
        </div>
      </header>

      {report.analysis_stopped && (
        <Alert variant="info">
          Analysis stopped after threat intelligence identified this sample as malware.
        </Alert>
      )}

      <div className="report-grid">
        {cape && (
          <section className="panel">
            <h2>CAPE Sandbox</h2>
            <dl className="kv-list">
              <dt>Status</dt>
              <dd>
                <span className={`badge badge-${String(capeStatus).toLowerCase()}`}>
                  {String(capeStatus).replaceAll("_", " ")}
                </span>
              </dd>
              {report.task_id != null && (
                <>
                  <dt>Task ID</dt>
                  <dd className="mono">{report.task_id}</dd>
                </>
              )}
              <dt>Report</dt>
              <dd>{cape.statistics ? "Fetched from CAPE" : "Not available"}</dd>
            </dl>
          </section>
        )}

        <section className="panel">
          <h2>Hashes</h2>
          {hashes && (
            <dl className="kv-list">
              <dt>MD5</dt>
              <dd className="mono">{hashes.md5}</dd>
              <dt>SHA1</dt>
              <dd className="mono">{hashes.sha1}</dd>
              <dt>SHA256</dt>
              <dd className="mono">{hashes.sha256}</dd>
            </dl>
          )}
        </section>

        <section className="panel">
          <h2>ML Classification</h2>
          {ml?.ready ? (
            <dl className="kv-list">
              <dt>Label</dt>
              <dd>{ml.label}</dd>
              {ml.risk_level && (
                <>
                  <dt>Classification Risk</dt>
                  <dd>{ml.risk_level.toUpperCase()}</dd>
                </>
              )}
              {ml.decision_source && (
                <>
                  <dt>Decision Source</dt>
                  <dd>{ml.decision_source.replaceAll("_", " ")}</dd>
                </>
              )}
              {ml.model_label && ml.model_label !== ml.label && (
                <>
                  <dt>Raw ML Label</dt>
                  <dd>{ml.model_label}</dd>
                </>
              )}
              <dt>Malware Probability</dt>
              <dd>{((ml.malware_probability ?? 0) * 100).toFixed(1)}%</dd>
              {ml.model_malware_probability != null && (
                <>
                  <dt>Raw ML Probability</dt>
                  <dd>{(ml.model_malware_probability * 100).toFixed(1)}%</dd>
                </>
              )}
            </dl>
          ) : (
            <p className="muted">{ml?.reason || "ML prediction not available for this sample."}</p>
          )}
        </section>

        {(risk?.factors || risk?.reasons) && (risk.factors || risk.reasons).length > 0 && (
          <section className="panel full-width">
            <h2>Risk Factors</h2>
            <ul className="factor-list">
              {(risk.factors || risk.reasons).map((factor, i) => (
                <li key={i}>{factor}</li>
              ))}
            </ul>
          </section>
        )}

        {iocs && Object.keys(iocs).length > 0 && (
          <section className="panel full-width">
            <h2>Indicators of Compromise</h2>
            {Object.entries(iocs).map(([key, values]) =>
              values.length > 0 ? (
                <div key={key} className="ioc-group">
                  <h3>{key}</h3>
                  <ul>
                    {values.slice(0, 20).map((v, i) => (
                      <li key={i} className="mono">
                        {v}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null
            )}
          </section>
        )}

        <section className="panel full-width">
          <h2>Full Report (JSON)</h2>
          <pre className="json-view">{JSON.stringify(report, null, 2)}</pre>
        </section>
      </div>
    </div>
  );
}
