import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Download,
  Globe2,
  Search,
  ShieldCheck,
} from "lucide-react";

const API = "/phishing-api";

async function readApiResponse(response) {
  const text = await response.text();
  if (!text.trim()) {
    throw new Error(`Phishing backend returned an empty response (HTTP ${response.status}).`);
  }

  const data = JSON.parse(text);
  if (!response.ok) throw new Error(data.detail || `Request failed (HTTP ${response.status}).`);
  return data;
}

function riskClass(category = "") {
  if (category === "Very High Risk" || category === "High Risk") return "risk-danger";
  if (category === "Medium Risk") return "risk-warning";
  return "risk-safe";
}

export default function Phishing() {
  const [url, setUrl] = useState("");
  const [metrics, setMetrics] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetch(`${API}/model-info`)
      .then(readApiResponse)
      .then(setMetrics)
      .catch((error) => setMessage(error.message));
  }, []);

  async function scanUrl(event) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const response = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      setResult(await readApiResponse(response));
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function downloadReport() {
    const response = await fetch(`${API}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(result),
    });
    if (!response.ok) {
      setMessage("Could not generate the PDF report.");
      return;
    }
    const link = document.createElement("a");
    link.href = URL.createObjectURL(await response.blob());
    link.download = "phishing_detection_report.pdf";
    link.click();
    URL.revokeObjectURL(link.href);
  }

  return (
    <div className="phishing-page">
      <header className="page-header">
        <div>
          <p className="eyebrow">URL THREAT INTELLIGENCE</p>
          <h1>Phishing Link Scanner</h1>
          <p className="muted">Analyze suspicious links with rules, machine learning, website analysis, and threat intelligence.</p>
        </div>
        <ShieldCheck aria-label="Protected analysis" />
      </header>

      {message && <div className="notice error">{message}</div>}

      <section className="card">
        <div className="section-heading">
          <div><span className="section-kicker">LIVE SCAN</span><h2>Enter URL</h2></div>
          <Globe2 />
        </div>
        <form onSubmit={scanUrl} className="scan-form">
          <input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/login" required />
          <button className="primary" disabled={loading}><Search size={18} />{loading ? "Scanning..." : "Scan URL"}</button>
        </form>
      </section>

      <PhishingWorkflow />

      {metrics && (
        <section className="card">
          <div className="section-heading"><div><span className="section-kicker">MODEL INFORMATION</span><h2>Random Forest</h2></div><Database /></div>
          <div className="metric-grid five">
            <Metric label="Accuracy" value={`${(metrics.accuracy * 100).toFixed(2)}%`} />
            <Metric label="Precision" value={`${(metrics.precision * 100).toFixed(2)}%`} />
            <Metric label="Recall" value={`${(metrics.recall * 100).toFixed(2)}%`} />
            <Metric label="F1 Score" value={`${(metrics.f1 * 100).toFixed(2)}%`} />
            <Metric label="ROC-AUC" value={`${(metrics.roc_auc * 100).toFixed(2)}%`} />
          </div>
          {metrics.fallback && (
            <div className="notice error">
              Training dataset unavailable. Scans are using heuristic fallback mode. Add <b>phishing link detection dataset.csv</b> to the backend folder to enable Random Forest training.
            </div>
          )}
        </section>
      )}

      {result && (
        <>
          <section className={`risk-banner ${riskClass(result.risk_category)}`}>
            <div><span className="section-kicker">DETECTION RESULT</span><h2>{result.risk_category}</h2><p>{result.url}</p></div>
            <div className="risk-score"><strong>{result.risk_score}</strong><span>/100</span></div>
          </section>
          <div className="metric-grid four">
            <Metric label="ML Prediction" value={result.ml_label} />
            <Metric label="Phishing Probability" value={`${Number(result.ml_probability).toFixed(2)}%`} />
            <Metric label="Risk Score" value={`${result.risk_score}/100`} />
            <Metric label="Indicators" value={result.indicators.length} />
          </div>
          <section className="card">
            <div className="section-heading"><div><span className="section-kicker">SECURITY INDICATORS</span><h2>Detected Indicators</h2></div><AlertTriangle /></div>
            <IndicatorList items={result.indicators} />
          </section>
          <section className="card">
            <div className="section-heading"><div><span className="section-kicker">FEATURE EXTRACTION</span><h2>Extracted URL Features</h2></div></div>
            <div className="table-wrap"><table><thead><tr><th>Feature</th><th>Value</th></tr></thead><tbody>{Object.entries(result.features).map(([feature, value]) => <tr key={feature}><td>{feature}</td><td>{String(value)}</td></tr>)}</tbody></table></div>
          </section>
          <button className="download" onClick={downloadReport}><Download size={18} />Download PDF Report</button>
        </>
      )}
    </div>
  );
}

function PhishingWorkflow() {
  return (
    <section className="card workflow-card" aria-labelledby="phishing-workflow-title">
      <div className="workflow-heading">
        <div>
          <span className="workflow-kicker">DETECTION FLOW</span>
          <h2 id="phishing-workflow-title">URL analysis workflow</h2>
          <p className="muted">
            Each scan combines model, rule, website, and available threat-intelligence signals.
          </p>
        </div>
      </div>
      <div className="workflow-flow">
        <div className="workflow-node workflow-input">Start · Enter URL</div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-hash">
          Normalize URL · Validate HTTP / HTTPS
        </div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-intel">
          Combined scan signals
          <small>
            URL features + Random Forest · Rule analysis · Website content · VirusTotal + Google Safe Browsing
          </small>
        </div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-risk">
          Weighted risk assessment
        </div>
        <div className="workflow-branches">
          <article className="workflow-path workflow-known">
            <h3>Legitimate URL</h3>
            <p>Show the safe result and supporting scan details.</p>
          </article>
          <article className="workflow-path workflow-unknown">
            <h3>Potential phishing</h3>
            <p>Show the risk score and detected security indicators.</p>
          </article>
        </div>
        <span className="workflow-arrow" aria-hidden="true">↓</span>
        <div className="workflow-node workflow-output">
          Scan result → Downloadable PDF report
        </div>
      </div>
    </section>
  );
}

function Metric({ label, value }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong></div>;
}

function IndicatorList({ items = [] }) {
  if (!items.length) return <div className="indicator safe"><CheckCircle2 size={17} /> No significant indicators detected.</div>;
  return <div className="indicator-list">{items.map((item, index) => <div className="indicator warning" key={`${item}-${index}`}><AlertTriangle size={17} /><span>{item}</span></div>)}</div>;
}