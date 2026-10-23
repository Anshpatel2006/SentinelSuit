import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Download,
  Globe,
  Search,
  Shield,
} from "lucide-react";
import { api } from "./api";
import "./workflow.css";

function Notice({ children, error = false }) {
  return <div className={error ? "notice error" : "notice"}><AlertTriangle size={17} />{children}</div>;
}

function Metric({ label, value }) {
  return <div className="stat-card phishing-metric"><div><span>{label}</span><strong>{value ?? "—"}</strong></div></div>;
}

function riskTone(category = "") {
  if (category.includes("Very High") || category.includes("High")) return "danger";
  if (category.includes("Medium")) return "warning";
  return "safe";
}

function Indicators({ items }) {
  if (!items?.length) {
    return <div className="safe-line"><CheckCircle2 size={16} /> No significant indicators reported.</div>;
  }
  return <ul className="indicator-list">{items.map((item, index) => <li key={`${item}-${index}`}><AlertTriangle size={16} />{item}</li>)}</ul>;
}

function Workflow() {
  return (
    <section className="panel workflow-panel" aria-labelledby="phishing-workflow-heading">
      <div className="panel-heading"><div><span className="eyebrow">DETECTION FLOW</span><h3 id="phishing-workflow-heading">URL analysis workflow</h3><p className="muted">The backend evaluates each URL in one independent scan request.</p></div></div>
      <div className="workflow-flow">
        <div className="workflow-node workflow-input">Enter URL</div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-validation">Normalize and validate HTTP / HTTPS URL</div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-intel">Threat-intelligence and analysis signals<small>VirusTotal · Google Safe Browsing · URL rules · Website content · Feature extraction · Random Forest</small></div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-risk">Combined risk assessment</div>
        <div className="workflow-branches">
          <article className="workflow-path workflow-known"><h4>Legitimate result</h4><p>Display the model result and supporting scan evidence.</p></article>
          <article className="workflow-path workflow-unknown"><h4>Potential phishing result</h4><p>Display risk level, security indicators, and safe next steps.</p></article>
        </div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-output">Result details · On-demand PDF report</div>
      </div>
    </section>
  );
}

export default function Phishing() {
  const [url, setUrl] = useState("");
  const [health, setHealth] = useState(null);
  const [model, setModel] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    let active = true;
    Promise.allSettled([api.phishingHealth(), api.phishingModel()]).then(([healthResult, modelResult]) => {
      if (!active) return;
      setHealth(healthResult.status === "fulfilled" ? healthResult.value : null);
      setModel(modelResult.status === "fulfilled" ? modelResult.value : null);
      if (healthResult.status === "rejected" && modelResult.status === "rejected") {
        setError(healthResult.reason?.message || modelResult.reason?.message || "Phishing service unavailable.");
      }
    });
    return () => { active = false; };
  }, []);

  async function scan(event) {
    event.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const value = url.trim();
      const normalized = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`;
      const parsed = new URL(normalized);
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
        throw new Error("Enter a valid HTTP or HTTPS URL without embedded credentials.");
      }
      setResult(await api.phishingScan(normalized));
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "URL analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  async function downloadReport() {
    if (!result) return;
    setDownloading(true);
    setError("");
    try {
      const response = await api.phishingReport(result);
      const blob = await response.blob();
      const fileUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = fileUrl;
      link.download = "phishing_detection_report.pdf";
      link.click();
      URL.revokeObjectURL(fileUrl);
    } catch (reportError) {
      setError(reportError instanceof Error ? reportError.message : "Could not generate the PDF report.");
    } finally {
      setDownloading(false);
    }
  }

  const riskScore = Number(result?.risk_score);
  const features = result?.features || {};
  const website = result?.website;
  const rules = result?.rules;
  const threatIntel = result?.virustotal;
  const safeBrowsing = result?.safe_browsing;

  return (
    <>
      <section className="page-intro">
        <div><span className="eyebrow">URL THREAT INTELLIGENCE</span><h2>Phishing link detection</h2><p>Analyze a URL using the existing rule, ML, website, and threat-intelligence service.</p></div>
        <span className={`live-indicator ${health ? "service-online" : "service-offline"}`}>{health ? "API ONLINE" : health === null ? "API STATUS UNKNOWN" : "API OFFLINE"}</span>
      </section>
      {error && <Notice error>{error}</Notice>}
      <section className="panel">
        <div className="panel-heading"><div><span className="eyebrow">INDEPENDENT URL SCAN</span><h3>Submit a link</h3></div><Globe size={19} /></div>
        <form className="scan-bar phishing-form" onSubmit={scan}>
          <Globe size={20} />
          <input type="text" inputMode="url" autoComplete="url" aria-label="URL to analyze" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/login" required />
          <button className="button primary" disabled={loading || !health}>{loading ? "Analyzing..." : <><Search size={16} /> Analyze URL</>}</button>
        </form>
        <p className="muted phishing-warning">Only submit URLs you are authorized to assess. Do not open suspicious links in your browser.</p>
      </section>
      <Workflow />
      <section className="panel">
        <div className="panel-heading"><div><span className="eyebrow">MODEL STATUS</span><h3>Prediction availability</h3></div><Database size={18} /></div>
        {model ? <><div className="stats-grid compact phishing-model-stats">
          <Metric label="Model" value={model.fallback ? "Heuristic fallback" : "Random Forest"} />
          {model.accuracy != null && <Metric label="Accuracy" value={`${(Number(model.accuracy) * 100).toFixed(2)}%`} />}
          {model.precision != null && <Metric label="Precision" value={`${(Number(model.precision) * 100).toFixed(2)}%`} />}
          {model.recall != null && <Metric label="Recall" value={`${(Number(model.recall) * 100).toFixed(2)}%`} />}
        </div>{model.fallback && <Notice>Training dataset is unavailable; the backend reports that heuristic fallback is active.</Notice>}</>
          : <p className="muted">Model information is not available from the phishing service.</p>}
      </section>
      {result && (
        <>
          <section className={`verdict ${riskTone(result.risk_category || "")}`}>
            <div><span className="eyebrow">DETECTION RESULT</span><h3>{result.risk_category || "Risk category unavailable"}</h3><p>{result.url}</p></div>
            <strong>{Number.isFinite(riskScore) ? riskScore.toFixed(1) : "—"}<small>/100</small></strong>
          </section>
          <div className="stats-grid compact">
            <Metric label="ML result" value={result.ml_label} />
            <Metric label="Phishing probability" value={Number.isFinite(Number(result.ml_probability)) ? `${Number(result.ml_probability).toFixed(1)}%` : "Unavailable"} />
            <Metric label="Risk score" value={Number.isFinite(riskScore) ? `${riskScore}/100` : "Unavailable"} />
            <Metric label="Indicators" value={result.indicators?.length ?? 0} />
          </div>
          <section className="panel">
            <div className="panel-heading"><div><span className="eyebrow">THREAT INTELLIGENCE</span><h3>External provider results</h3></div><Database size={18} /></div>
            <div className="stats-grid compact">
              <Metric label="VirusTotal malicious" value={threatIntel?.malicious ?? "Unavailable"} />
              <Metric label="VirusTotal suspicious" value={threatIntel?.suspicious ?? "Unavailable"} />
              <Metric label="Safe Browsing threats" value={safeBrowsing?.threats?.length ?? "Unavailable"} />
            </div>
            <Indicators items={result.threat_indicators || []} />
          </section>
          <section className="panel">
            <div className="panel-heading"><div><span className="eyebrow">RULE ANALYSIS</span><h3>URL heuristics</h3></div></div>
            {rules && <><p className="large-score">{rules.score ?? "—"}<span>/100 rule score</span></p>{rules.keywords?.length > 0 && <p className="muted">Suspicious keywords: {rules.keywords.join(", ")}</p>}</>}
            <Indicators items={rules?.indicators || []} />
          </section>
          <section className="panel">
            <div className="panel-heading"><div><span className="eyebrow">WEBSITE ANALYSIS</span><h3>Fetched page signals</h3></div><Globe size={18} /></div>
            {website ? <>
              <div className="stats-grid compact">
                <Metric label="Accessible" value={website.accessible == null ? "Unavailable" : website.accessible ? "Yes" : "No"} />
                <Metric label="Forms" value={website.forms ?? "Unavailable"} />
                <Metric label="Password fields" value={website.password_inputs ?? "Unavailable"} />
                <Metric label="External links" value={website.external_links ?? "Unavailable"} />
              </div>
              {website.title && <p className="muted"><strong>Page title:</strong> {website.title}</p>}
              <Indicators items={website.indicators || []} />
            </> : <p className="muted">Website-analysis details are not present in this scan response.</p>}
          </section>
          <section className="panel">
            <div className="panel-heading"><div><span className="eyebrow">FEATURE EXTRACTION</span><h3>Observed URL features</h3></div></div>
            <div className="feature-grid">{Object.entries(features).map(([key, value]) => <div key={key}><span>{key.replaceAll("_", " ")}</span><strong>{String(value)}</strong></div>)}</div>
            {!Object.keys(features).length && <p className="muted">No URL feature data was returned.</p>}
          </section>
          <section className="panel recommended-response">
            <div className="panel-heading"><div><span className="eyebrow">SAFE NEXT STEPS</span><h3>Recommended response</h3></div><Shield size={18} /></div>
            {result.ml_label === "Phishing" || riskScore >= 40
              ? <p className="muted">Do not enter credentials or payment details. Verify the request using the organization’s known official website or contact channel.</p>
              : <p className="muted">A low-risk result is not a guarantee of safety. Verify the sender and destination before sharing sensitive information.</p>}
          </section>
          <section className="panel">
            <div className="panel-heading"><div><span className="eyebrow">SECURITY INDICATORS</span><h3>All scan indicators</h3></div></div>
            <Indicators items={result.indicators || []} />
            <button className="button secondary report-action" onClick={downloadReport} disabled={downloading}>{downloading ? "Preparing report..." : <><Download size={16} /> Download PDF report</>}</button>
          </section>
        </>
      )}
    </>
  );
}
