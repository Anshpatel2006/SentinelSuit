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
  const [fullAnalysis, setFullAnalysis] = useState(false);
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
      setJob(await api.ransomwareUpload(file, fullAnalysis));
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

  const stages = fullAnalysis
    ? ["Preparing sample", "Static analysis", "CAPE sandbox", "ML analysis", "Report ready"]
    : ["Preparing sample", "Generate hashes", "VirusTotal + MalwareBazaar", "Report ready"];
  const currentStage = job?.status === "completed"
    ? "Report ready"
    : job?.status === "failed"
      ? "Analysis failed"
      : job?.current_stage || "Queued";
  const stageIndex = (() => {
    const value = currentStage.toLowerCase();
    if (value.includes("report") || value.includes("risk") || value.includes("complete")) return stages.length - 1;
    if (fullAnalysis && (value.includes("machine-learning") || value.includes("ml") || value.includes("memory"))) return 3;
    if (fullAnalysis && (value.includes("cape") || value.includes("sandbox"))) return 2;
    if (fullAnalysis && value.includes("static")) return 1;
    if (fullAnalysis && (value.includes("virus") || value.includes("malwarebazaar") || value.includes("threat"))) return 1;
    if (!fullAnalysis && (value.includes("virus") || value.includes("malwarebazaar") || value.includes("threat"))) return 2;
    if (value.includes("hash")) return 1;
    if (value.includes("prepar") || value.includes("upload") || value.includes("threat")) return 0;
    return job?.status === "completed" ? stages.length - 1 : 0;
  })();

  return <>
    <section className="page-intro">
      <div><span className="eyebrow">FILE ANALYSIS / MALWARE PLATFORM</span><h2>Ransomware analysis</h2><p>Choose threat-intelligence lookup only or full analysis with the CAPE sandbox.</p></div>
      <Badge level="info">POST /api/v1/analyze</Badge>
    </section>
    {error && <Notice>{error}</Notice>}
    <section className="panel workflow-panel" aria-labelledby="ransomware-workflow-heading">
      <div className="panel-heading"><div><span className="eyebrow">ANALYSIS FLOW</span><h3 id="ransomware-workflow-heading">File analysis workflow</h3><p className="muted">{fullAnalysis ? "Full mode adds static analysis, CAPE sandbox submission, memory analysis, and ML classification after threat-intelligence lookups." : "Lookup-only mode checks VirusTotal and MalwareBazaar and does not submit the file to CAPE."}</p></div></div>
      <div className="workflow-flow">
        <div className="workflow-node workflow-input">Upload sample</div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-validation">Validate and store file · Generate MD5 / SHA-1 / SHA-256</div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-intel">VirusTotal + MalwareBazaar lookup</div>
        {fullAnalysis && <>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
          <div className="workflow-node workflow-validation">Static analysis · CAPE sandbox · Memory features · ML</div>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
        </>}
        {!fullAnalysis && <span className="workflow-arrow" aria-hidden="true">↓</span>}
        <div className="workflow-node workflow-output">Risk assessment · JSON / HTML / PDF report</div>
      </div>
    </section>
    <form className="upload-panel" onSubmit={submit}>
      <fieldset className="cape-option">
        <legend>Analysis mode</legend>
        <label><input type="radio" name="analysis-mode" checked={!fullAnalysis} onChange={() => setFullAnalysis(false)} /><span><strong>VirusTotal + MalwareBazaar only</strong><small>Hash lookups and report; no CAPE submission.</small></span></label>
        <label><input type="radio" name="analysis-mode" checked={fullAnalysis} onChange={() => setFullAnalysis(true)} /><span><strong>Full analysis including CAPE</strong><small>Static analysis, sandbox, memory features, and ML classification.</small></span></label>
      </fieldset>
      <label className="dropzone"><UploadCloud size={30} /><strong>{file ? file.name : "Choose a suspicious sample"}</strong><span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB selected` : "The original service validates and stores the upload"}</span><input type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} /></label>
      <div className="upload-actions">
        <button className="button primary" disabled={!file || submitting}>{submitting ? "Submitting..." : fullAnalysis ? "Start full analysis" : "Start analysis"}</button>
      </div>
    </form>
    {job && <section className="panel result-panel"><div className="panel-heading"><div><span className="eyebrow">ANALYSIS JOB</span><h3>{job.filename || file?.name}</h3></div><div className="result-actions"><Badge level={job.status === "failed" ? "critical" : job.status === "completed" ? "safe" : "warning"}>{job.status}</Badge>{job.sample_id && job.status === "completed" && <><button className="icon-button report-download-icon" type="button" onClick={downloadReport} disabled={!report} title="Download PDF report" aria-label="Download PDF report"><Download size={17} /></button><button className="button secondary" type="button" onClick={downloadJsonReport} disabled={!report}><Download size={16} />JSON</button><button className="button secondary" type="button" onClick={downloadReport} disabled={!report}><Download size={16} />PDF</button></>}</div></div><div className="flow-steps" aria-label="Analysis progress">{stages.map((stage, index) => <div className={`flow-step ${index < stageIndex || job.status === "completed" ? "done" : ""} ${index === stageIndex && job.status !== "completed" ? "active" : ""}`} key={stage}><span>{index < stageIndex || job.status === "completed" ? "✓" : index + 1}</span><small>{stage}</small></div>)}</div><p className="current-stage">{currentStage}</p><div className="progress-track"><span style={{ width: job.status === "completed" || job.status === "failed" ? "100%" : `${Math.max(12, ((stageIndex + 1) / stages.length) * 100)}%` }} /></div><div className="result-meta"><span>Job ID<strong>{job.job_id}</strong></span><span>Sample ID<strong>{job.sample_id || "Pending"}</strong></span><span>Threat intel<strong>{report?.threat_intel?.known ? report.threat_intel.malicious ? "Malicious" : "Known" : "No match"}</strong></span>{job.full_analysis && <><span>CAPE<strong>{report?.cape?.status || report?.cape?.task?.status || "Pending"}</strong></span><span>ML<strong>{report?.ml?.ready ? report.ml.label : report?.ml?.reason || "Pending"}</strong></span></>}<span>Risk<strong>{report?.risk?.level || "Pending"}</strong></span></div>{job.error && <Notice>{job.error}</Notice>}</section>}
    <section className="info-strip"><FileSearch size={19} /><div><strong>{fullAnalysis ? "Full malware analysis" : "Threat-intelligence-only analysis"}</strong><p>{fullAnalysis ? "Full mode uses static analysis, the configured CAPE sandbox, memory features, and ML. Run it only with a trusted, isolated CAPE environment." : "Checks VirusTotal and MalwareBazaar by file hash. No sample is submitted to CAPE."}</p></div></section>
  </>;
}
