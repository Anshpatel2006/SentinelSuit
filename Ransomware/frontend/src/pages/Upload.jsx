import { useCallback, useRef, useState } from "react";
import { uploadSample } from "../api/client";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { useJobPolling } from "../hooks/useJobPolling";

export default function Upload() {
  const [dragging, setDragging] = useState(false);
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");
  const [continueToCape, setContinueToCape] = useState(false);
  const inputRef = useRef(null);

  useJobPolling(job, setJob);

  const handleFile = useCallback(async (file) => {
    setError("");
    setJob(null);
    try {
      const newJob = await uploadSample(file, continueToCape);
      setJob(newJob);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    }
  }, [continueToCape]);

  return (
    <div>
      <PageHeader
        title="Upload Sample"
        subtitle="Submit a file for hybrid static, dynamic, and ML analysis"
      />

      {error && <Alert>{error}</Alert>}

      <section className="panel workflow-panel" aria-labelledby="file-workflow-title">
        <div className="workflow-heading">
          <div>
            <span className="workflow-kicker">ANALYSIS ENGINE</span>
            <h2 id="file-workflow-title">File analysis workflow</h2>
            <p className="muted">
              Hash-based threat intelligence routes known malware to an early report; other
              samples continue through static and sandbox analysis.
            </p>
          </div>
        </div>
        <div className="workflow-flow">
          <div className="workflow-node workflow-input">Start · Upload sample</div>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
          <div className="workflow-node workflow-hash">
            Generate MD5, SHA-1, and SHA-256 hashes · Check digital signature
          </div>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
          <div className="workflow-node workflow-intel">
            Threat intelligence lookup · VirusTotal + MalwareBazaar
          </div>
          <div className="workflow-branches">
            <article className="workflow-path workflow-known">
              <h3>Known malicious</h3>
              <p>
                Generate an early detection report. CAPE can still run when
                “Continue to CAPE” is enabled.
              </p>
            </article>
            <article className="workflow-path workflow-unknown">
              <h3>Unknown or continued sample</h3>
              <p>
                Static analysis → CAPE sandbox → memory-feature extraction →
                MalMem-55 ML classification → IOC extraction
              </p>
            </article>
          </div>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
          <div className="workflow-node workflow-output">
            Risk assessment → JSON / HTML / PDF report → Dashboard
          </div>
        </div>
      </section>

      <div
        className={`dropzone ${dragging ? "dragging" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files[0];
          if (file) handleFile(file);
        }}
        onClick={() => inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          hidden
          accept=".exe,.dll,.scr,.msi,.jar,.pdf,.doc,.docx,.bin"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />
        <div className="dropzone-icon">📁</div>
        <p>Drag & drop a sample here, or click to browse</p>
        <p className="muted small">Supported: exe, dll, scr, msi, jar, pdf, doc, bin (max 200 MB)</p>
      </div>

      <label className="analysis-option">
        <input
          type="checkbox"
          checked={continueToCape}
          onChange={(event) => setContinueToCape(event.target.checked)}
        />
        <span>
          <strong>Continue to CAPE if malware is detected</strong>
          <small>Use this for deeper sandbox analysis after VirusTotal or MalwareBazaar flags the sample.</small>
        </span>
      </label>

      {job && (
        <div className="panel job-status">
          <h3>Analysis Job</h3>
          <div className="job-meta">
            <span className="mono">{job.job_id.slice(0, 8)}…</span>
            <span className={`badge badge-${job.status}`}>{job.status}</span>
          </div>
          <p>{job.filename}</p>
          <p className="current-stage">{job.current_stage || "Processing analysis"}</p>
          {job.status === "running" && (
            <div className="progress-bar">
              <div className="progress-fill animate" />
            </div>
          )}
          {job.status === "failed" && <p className="text-danger">{job.error}</p>}
        </div>
      )}
    </div>
  );
}
