import { useEffect, useState } from "react";
import { AlertTriangle, Download, FileSearch, Shield, UploadCloud } from "lucide-react";
import { api } from "./api";
import "./ransomware.css";
import "./workflow.css";

function Badge({ children, level = "info" }) {
  return <span className={`badge ${level}`}>{children}</span>;
}

function Notice({ children }) {
  return <div className="notice error"><AlertTriangle size={17} />{children}</div>;
}

export default function Ransomware() {
  const [file, setFile] = useState(null);
  const [continueToCape, setContinueToCape] = useState(false);
  const [job, setJob] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (job?.status !== "completed" || !job.sample_id) return undefined;
    if (job.result) {
      setReport(job.result);
      return undefined;
    }
    let cancelled = false;
    api.ransomwareReport(job.sample_id)
      .then((result) => {
        if (!cancelled) setReport(result);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [job?.status, job?.sample_id]);

  useEffect(() => {
    if (!job?.job_id || ["completed", "failed"].includes(job.status)) return undefined;
    const timer = setInterval(() => {
      api.ransomwareJob(job.job_id).then(setJob).catch((err) => setError(err.message));
    }, 2000);
    return () => clearInterval(timer);
  }, [job]);

  async function submit(event) {
    event.preventDefault();
    if (!file) return;
    setSubmitting(true);
    setError("");
    setReport(null);
    try {
      setJob(await api.ransomwareUpload(file, continueToCape));
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function downloadReport() {
    if (!job?.sample_id) return;
    try {
      const response = await api.ransomwareReportPdf(job.sample_id);
      if (!response.ok) {
        setError("The ransomware report is not available yet.");
        return;
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `${job.sample_id}-report.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message);
    }
  }

  function downloadJsonReport() {
    if (!report || !job?.sample_id) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" })
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `${job.sample_id}-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  const ml = report?.ml;
  const cape = report?.cape;
  const capeStatus = cape?.status || cape?.task?.status || (cape?.statistics ? "reported" : "not available");
  const stages = ["Preparing sample", "Static analysis", "CAPE sandbox", "ML analysis", "Report ready"];
  const currentStage = job?.status === "completed"
    ? "Report ready"
    : job?.status === "failed"
      ? "Analysis failed"
      : job?.current_stage || "Queued";
  const stageIndex = (() => {
    const value = currentStage.toLowerCase();
    if (value.includes("report") || value.includes("risk") || value.includes("indicator")) return 4;
    if (value.includes("machine-learning") || value.includes("ml") || value.includes("memory")) return 3;
    if (value.includes("cape") || value.includes("sandbox")) return 2;
    if (value.includes("static") || value.includes("signature") || value.includes("hash")) return 1;
    if (value.includes("prepar") || value.includes("upload") || value.includes("threat")) return 0;
    return job?.status === "completed" ? 4 : 0;
  })();

  return <>
    <section className="page-intro">
      <div><span className="eyebrow">FILE ANALYSIS / MALWARE PLATFORM</span><h2>Ransomware analysis</h2><p>Submit a sample to the existing static, ML, and optional CAPE pipeline.</p></div>
      <Badge level="info">POST /api/v1/analyze</Badge>
    </section>
    {error && <Notice>{error}</Notice>}
    <section className="panel workflow-panel" aria-labelledby="ransomware-workflow-heading">
      <div className="panel-heading"><div><span className="eyebrow">ANALYSIS FLOW</span><h3 id="ransomware-workflow-heading">File analysis workflow</h3><p className="muted">Known malware can stop after intelligence checks unless CAPE continuation is requested.</p></div></div>
      <div className="workflow-flow">
        <div className="workflow-node workflow-input">Upload sample</div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-validation">Validate and store file · Generate MD5 / SHA-1 / SHA-256 · Check signature</div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-intel">VirusTotal + MalwareBazaar lookup</div>
        <div className="workflow-branches">
          <article className="workflow-path workflow-known"><h4>Known malicious</h4><p>Write an early detection report; continue to CAPE only when explicitly enabled.</p></article>
          <article className="workflow-path workflow-unknown"><h4>Unknown or continued sample</h4><p>Static analysis → optional CAPE sandbox → memory feature extraction → ML classification when features are available → IOC extraction.</p></article>
        </div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-output">Risk assessment · JSON / HTML / PDF report</div>
      </div>
    </section>
    <form className="upload-panel" onSubmit={submit}>
      <label className="dropzone"><UploadCloud size={30} /><strong>{file ? file.name : "Choose a suspicious sample"}</strong><span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB selected` : "The original service validates and stores the upload"}</span><input type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} /></label>
      <div className="upload-actions">
        <label className="cape-option"><input type="checkbox" checked={continueToCape} onChange={(event) => setContinueToCape(event.target.checked)} /><span><strong>Continue to CAPE Sandbox</strong><small>Submit the sample to the live CAPE task API after the analysis pipeline reaches that stage.</small></span></label>
        <button className="button primary" disabled={!file || submitting}>{submitting ? "Submitting..." : continueToCape ? "Start with CAPE" : "Start analysis"}</button>
      </div>
    </form>
    {job && <section className="panel result-panel"><div className="panel-heading"><div><span className="eyebrow">ANALYSIS JOB</span><h3>{job.filename || file?.name}</h3></div><div className="result-actions"><Badge level={job.status === "failed" ? "critical" : job.status === "completed" ? "safe" : "warning"}>{job.status}</Badge>{job.sample_id && job.status === "completed" && <><button className="icon-button report-download-icon" type="button" onClick={downloadReport} disabled={!report} title="Download PDF report" aria-label="Download PDF report"><Download size={17} /></button><button className="button secondary" type="button" onClick={downloadJsonReport} disabled={!report}><Download size={16} />JSON</button><button className="button secondary" type="button" onClick={downloadReport} disabled={!report}><Download size={16} />PDF</button></>}</div></div><div className="flow-steps" aria-label="Analysis progress">{stages.map((stage, index) => <div className={`flow-step ${index < stageIndex || job.status === "completed" ? "done" : ""} ${index === stageIndex && job.status !== "completed" ? "active" : ""}`} key={stage}><span>{index < stageIndex || job.status === "completed" ? "✓" : index + 1}</span><small>{stage}</small></div>)}</div><p className="current-stage">{currentStage}</p><div className="progress-track"><span style={{ width: job.status === "completed" || job.status === "failed" ? "100%" : `${Math.max(12, ((stageIndex + 1) / stages.length) * 100)}%` }} /></div><div className="result-meta"><span>Job ID<strong>{job.job_id}</strong></span><span>Sample ID<strong>{job.sample_id || "Pending"}</strong></span><span>CAPE<strong>{capeStatus}</strong></span><span>Risk<strong>{report?.risk?.level || "Pending"}</strong></span></div>{report && <div className="analysis-summary"><div><span className="eyebrow">ML ANALYSIS</span><strong>{ml?.ready ? ml.label : "Unavailable"}</strong><small>{ml?.ready ? `${((ml.malware_probability ?? 0) * 100).toFixed(1)}% malware probability` : ml?.reason || "ML prediction was not available."}</small></div><div><span className="eyebrow">CAPE REPORT</span><strong>{cape?.statistics ? "Fetched" : "Not available"}</strong><small>{report.task_id ? `Task ${report.task_id}` : `Status: ${capeStatus}`}</small></div></div>}{job.error && <Notice>{job.error}</Notice>}</section>}
    <section className="info-strip"><FileSearch size={19} /><div><strong>Preserved pipeline</strong><p>Static analysis, YARA, intelligence lookups, memory features, ML scoring, CAPE, and report generation remain in the original service.</p></div></section>
  </>;
}
