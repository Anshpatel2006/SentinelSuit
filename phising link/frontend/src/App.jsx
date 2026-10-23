import { useEffect, useState } from "react";
import {
  ShieldCheck,
  Search,
  Download,
  AlertTriangle,
  CheckCircle2,
  Globe2,
  BrainCircuit,
  ListChecks,
  Database
} from "lucide-react";
import {
  BarChart,
  Bar,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

const API = "/api";

async function readApiResponse(response) {
  const text = await response.text();
  if (!text.trim()) {
    throw new Error(`Backend returned an empty response (HTTP ${response.status}). Make sure FastAPI is running on port 8000.`);
  }

  try {
    const data = JSON.parse(text);
    if (!response.ok) {
      throw new Error(data.detail || `Request failed (HTTP ${response.status}).`);
    }
    return data;
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw new Error(`Backend returned a non-JSON response (HTTP ${response.status}). Start the FastAPI backend and check its terminal for the actual error.`);
    }
    throw err;
  }
}

function pct(v) {
  return `${Number(v || 0).toFixed(2)}%`;
}

function riskClass(category = "") {
  if (category === "Very High Risk" || category === "High Risk") return "risk-danger";
  if (category === "Medium Risk") return "risk-warning";
  return "risk-safe";
}

export default function App() {
  const [url, setUrl] = useState("");
  const [metrics, setMetrics] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [backendError, setBackendError] = useState("");

  useEffect(() => {
    fetch(`${API}/model-info`)
      .then(readApiResponse)
      .then(setMetrics)
      .catch(err => setBackendError(err.message || "Could not connect to the Python backend."));
  }, []);

  async function scanUrl(e) {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    setBackendError("");

    try {
      const response = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url
        })
      });

      const data = await readApiResponse(response);
      if (!response.ok) throw new Error(data.detail || "Scan failed.");
      setResult(data);
    } catch (err) {
      setMessage(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function downloadReport() {
    if (!result) return;

    const response = await fetch(`${API}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(result)
    });

    if (!response.ok) {
      setMessage("Could not generate the PDF report.");
      return;
    }

    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "phishing_detection_report.pdf";
    link.click();
    URL.revokeObjectURL(link.href);
  }

  const probabilityData = result
    ? [
        { name: "Legitimate", probability: 100 - result.ml_probability },
        { name: "Phishing", probability: result.ml_probability }
      ]
    : [];

  const riskData = result
    ? [
        { name: "ML", score: result.component_scores.ml },
        { name: "Rules", score: result.component_scores.rules },
        { name: "Website", score: result.component_scores.website },
        { name: "Threat Intel", score: result.component_scores.threat_intelligence }
      ]
    : [];

  return (
    <div className="app-shell">
      <main className="main">
        <header className="hero">
          <div>
            <div className="eyebrow">CYBERSECURITY ANALYTICS</div>
            <h1>Phishing Link Detection System</h1>
            <p>
              Multi-layer phishing URL detection using URL features, rules,
              Random Forest, website analysis and threat intelligence.
            </p>
          </div>
          <div className="hero-badge"><ShieldCheck size={18} /> Protected analysis</div>
        </header>

        {backendError && <div className="notice error">{backendError}</div>}
        {message && <div className="notice error">{message}</div>}

        <section className="card scan-card">
          <div className="section-heading">
            <div>
              <span className="section-kicker">LIVE SCAN</span>
              <h2>Enter URL</h2>
            </div>
            <Globe2 size={24} />
          </div>

          <form onSubmit={scanUrl} className="scan-form">
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              required
            />
            <button className="primary" disabled={loading}>
              <Search size={18} />
              {loading ? "Scanning..." : "Scan URL"}
            </button>
          </form>
        </section>

        <PhishingWorkflow />

        {metrics && (
          <section className="card">
            <div className="section-heading">
              <div>
                <span className="section-kicker">MODEL INFORMATION</span>
                <h2>Random Forest</h2>
              </div>
              <BrainCircuit size={24} />
            </div>
            <div className="metric-grid five">
              <Metric label="Accuracy" value={pct(metrics.accuracy * 100)} />
              <Metric label="Precision" value={pct(metrics.precision * 100)} />
              <Metric label="Recall" value={pct(metrics.recall * 100)} />
              <Metric label="F1 Score" value={pct(metrics.f1 * 100)} />
              <Metric label="ROC-AUC" value={pct(metrics.roc_auc * 100)} />
            </div>
            <div className="model-note">
              Dataset rows: {metrics.rows.toLocaleString()} · Training rows:{" "}
              {metrics.train_rows.toLocaleString()} · Testing rows:{" "}
              {metrics.test_rows.toLocaleString()} · 200 estimators · balanced class weights
            </div>
          </section>
        )}

        {result && (
          <>
            <section className={`risk-banner ${riskClass(result.risk_category)}`}>
              <div>
                <span className="section-kicker">DETECTION RESULT</span>
                <h2>{result.risk_category}</h2>
                <p>{result.url}</p>
              </div>
              <div className="risk-score">
                <strong>{result.risk_score}</strong>
                <span>/100</span>
              </div>
            </section>

            <section className="metric-grid four">
              <Metric label="ML Prediction" value={result.ml_label} />
              <Metric label="Phishing Probability" value={pct(result.ml_probability)} />
              <Metric label="Risk Score" value={`${result.risk_score}/100`} />
              <Metric label="Risk Category" value={result.risk_category} />
            </section>

            <div className="two-col">
              <section className="card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">MACHINE LEARNING</span>
                    <h2>Prediction Analysis</h2>
                  </div>
                  <BrainCircuit size={24} />
                </div>
                <p><b>Model:</b> Random Forest Classifier</p>
                <p><b>Prediction:</b> {result.ml_label}</p>
                <p><b>Phishing probability:</b> {pct(result.ml_probability)}</p>
                <div className="chart">
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={probabilityData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis domain={[0, 100]} />
                      <Tooltip formatter={(v) => `${Number(v).toFixed(2)}%`} />
                      <Bar dataKey="probability" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </section>

              <section className="card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">RULE ANALYSIS</span>
                    <h2>URL Heuristics</h2>
                  </div>
                  <ListChecks size={24} />
                </div>
                <div className="large-score">{result.rules.score}<span>/100</span></div>
                {result.rules.keywords.length > 0 && (
                  <p><b>Suspicious keywords:</b> {result.rules.keywords.join(", ")}</p>
                )}
                <IndicatorList items={result.rules.indicators} />
              </section>
            </div>

            <section className="card">
              <div className="section-heading">
                <div>
                  <span className="section-kicker">WEBSITE ANALYSIS</span>
                  <h2>Website Content</h2>
                </div>
                <Globe2 size={24} />
              </div>
              <div className="metric-grid four">
                <Metric label="Accessible" value={result.website.accessible ? "Yes" : "No"} />
                <Metric label="Forms" value={result.website.forms} />
                <Metric label="Password Fields" value={result.website.password_inputs} />
                <Metric label="External Links" value={result.website.external_links} />
              </div>
              {result.website.title && <p className="page-title"><b>Page title:</b> {result.website.title}</p>}
              <IndicatorList items={result.website.indicators} />
            </section>

            <section className="card">
              <div className="section-heading">
                <div>
                  <span className="section-kicker">THREAT INTELLIGENCE</span>
                  <h2>External Signals</h2>
                </div>
                <Database size={24} />
              </div>
              <div className="metric-grid three">
                <Metric label="VirusTotal Malicious" value={result.virustotal.malicious} />
                <Metric label="VirusTotal Suspicious" value={result.virustotal.suspicious} />
                <Metric label="Google Threats" value={result.safe_browsing.threats.length} />
              </div>
              <IndicatorList items={result.threat_indicators} />
            </section>

            <section className="card">
              <div className="section-heading">
                <div>
                  <span className="section-kicker">FEATURE EXTRACTION</span>
                  <h2>Extracted URL Features</h2>
                </div>
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Feature</th><th>Value</th></tr></thead>
                  <tbody>
                    {Object.entries(result.features).map(([feature, value]) => (
                      <tr key={feature}><td>{feature}</td><td>{String(value)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="card">
              <div className="section-heading">
                <div>
                  <span className="section-kicker">RISK ASSESSMENT</span>
                  <h2>Risk Components</h2>
                </div>
                <AlertTriangle size={24} />
              </div>
              <div className="chart">
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={riskData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis domain={[0, 100]} />
                    <Tooltip />
                    <Bar dataKey="score" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="formula">
                Final score = ML × 50% + Rules × 25% + Website × 10% + Threat Intelligence × 15%
              </div>
            </section>

            <section className="card">
              <div className="section-heading">
                <div>
                  <span className="section-kicker">SECURITY INDICATORS</span>
                  <h2>Detected Indicators</h2>
                </div>
              </div>
              <IndicatorList items={result.indicators} />
            </section>

            <button className="download" onClick={downloadReport}>
              <Download size={18} />
              Download PDF Report
            </button>
          </>
        )}

        <footer>
          Phishing Link Detection Module · Random Forest + Rules + Website Analysis + Threat Intelligence
        </footer>
      </main>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PhishingWorkflow() {
  return (
    <section className="card workflow-card" aria-labelledby="phishing-workflow-title">
      <div className="section-heading">
        <div>
          <span className="section-kicker">DETECTION FLOW</span>
          <h2 id="phishing-workflow-title">URL analysis workflow</h2>
          <p className="workflow-description">
            Every scan combines the model, rule, website, and available threat-intelligence signals.
          </p>
        </div>
        <ListChecks size={24} />
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
        <div className="workflow-node workflow-risk">Weighted risk assessment</div>
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
          Scan result → Dashboard details / PDF report
        </div>
      </div>
    </section>
  );
}

function IndicatorList({ items = [] }) {
  if (!items.length) {
    return <div className="indicator safe"><CheckCircle2 size={17} /> No significant indicators detected.</div>;
  }
  return (
    <div className="indicator-list">
      {items.map((item, i) => (
        <div className="indicator warning" key={`${item}-${i}`}>
          <AlertTriangle size={17} />
          <span>{item}</span>
        </div>
      ))}
    </div>
  );
}
