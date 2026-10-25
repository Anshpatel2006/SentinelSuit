import { useCallback, useRef, useState } from "react";
import { uploadSample } from "../api/client";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { useJobPolling } from "../hooks/useJobPolling";

export default function Upload() {
  const [dragging, setDragging] = useState(false);
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");
  const [fullAnalysis, setFullAnalysis] = useState(false);
  const inputRef = useRef(null);

  useJobPolling(job, setJob);

  const handleFile = useCallback(async (file) => {
    setError("");
    setJob(null);
    try {
      const newJob = await uploadSample(file, fullAnalysis);
      setJob(newJob);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    }
  }, [fullAnalysis]);

  return (
    <div>
      <PageHeader
        title="Upload Sample"
        subtitle="Choose threat-intelligence lookup only or the full analysis pipeline"
      />

      {error && <Alert>{error}</Alert>}

      <section className="panel workflow-panel" aria-labelledby="file-workflow-title">
        <div className="workflow-heading">
          <div>
            <span className="workflow-kicker">ANALYSIS ENGINE</span>
            <h2 id="file-workflow-title">File analysis workflow</h2>
            <p className="muted">
              Choose whether to stop after VirusTotal and MalwareBazaar lookups or continue
              through static analysis, CAPE sandbox, and machine-learning analysis.
            </p>
          </div>
        </div>
        <div className="workflow-flow">
          <div className="workflow-node workflow-input">Start · Upload sample</div>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
          <div className="workflow-node workflow-hash">
            Generate MD5, SHA-1, and SHA-256 hashes
          </div>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
          <div className="workflow-node workflow-intel">
            Threat intelligence lookup · VirusTotal + MalwareBazaar
          </div>
          <span className="workflow-arrow" aria-hidden="true">↓</span>
          <div className="workflow-node workflow-output">
            Risk assessment → JSON / HTML / PDF report → Dashboard
          </div>
        </div>
      </section>

      <fieldset className="analysis-option">
        <legend>Analysis mode</legend>
        <label>
          <input
            type="radio"
            name="analysis-mode"
            checked={!fullAnalysis}
            onChange={() => setFullAnalysis(false)}
          />
          <span>
            <strong>VirusTotal + MalwareBazaar only</strong>
            <small>Check hashes and generate a report. Do not submit the file to CAPE.</small>
          </span>
        </label>
        <label>
          <input
            type="radio"
            name="analysis-mode"
            checked={fullAnalysis}
            onChange={() => setFullAnalysis(true)}
          />
          <span>
            <strong>Full analysis including CAPE</strong>
            <small>Run static analysis, then submit the sample to the configured CAPE sandbox.</small>
          </span>
        </label>
      </fieldset>

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
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />
        <div className="dropzone-icon">📁</div>
        <p>Drag & drop a sample here, or click to browse</p>
        <p className="muted small">All file extensions supported (max 250 MiB)</p>
      </div>

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
