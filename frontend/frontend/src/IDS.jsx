import { useEffect, useState } from "react";
import { Activity, AlertTriangle, Download, FileSearch, Radio, ShieldAlert, Wifi } from "lucide-react";
import { api } from "./api";
import "./ids.css";
import "./workflow.css";

function Badge({ children, level = "info" }) {
  return <span className={`badge ${String(level).toLowerCase()}`}>{children}</span>;
}

function Stat({ label, value, detail, icon: Icon, tone = "cyan" }) {
  return <div className="stat-card"><div className={`stat-icon ${tone}`}><Icon size={19} /></div><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></div>;
}

function formatTime(timestamp) {
  if (!timestamp) return "No packet recorded";
  const date = typeof timestamp === "number"
    ? new Date(timestamp * 1000)
    : new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleTimeString();
}

function saveReport(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sentinelids-full-report-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

export default function IDS() {
  const [summary, setSummary] = useState(null);
  const [capture, setCapture] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    let active = true;
    async function refresh() {
      const results = await Promise.allSettled([api.idsSummary(), api.idsAlerts(), api.idsCaptureStatus()]);
      if (!active) return;
      const [summaryResult, alertsResult, captureResult] = results;
      setSummary(summaryResult.value || null);
      const nextAlerts = alertsResult.value || [];
      const uniqueAlerts = [...new Map(nextAlerts.map((alert) => [`${alert.attack}-${alert.source_ip}-${alert.destination_ip}-${alert.protocol}-${alert.severity}-${alert.risk_score}`, alert])).values()];
      setAlerts(uniqueAlerts);
      setCapture(captureResult.value || null);
      const failure = results.find((result) => result.status === "rejected");
      setError(failure ? failure.reason.message : "");
    }
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  const latestAlert = alerts[0];
  async function downloadFullReport() {
    setDownloading(true);
    try {
      saveReport(await api.idsFullReport());
    } catch (downloadError) {
      setError(downloadError.message);
    } finally {
      setDownloading(false);
    }
  }

  return <><section className="page-intro"><div><span className="eyebrow">NETWORK TELEMETRY / IDS SERVICE</span><h2>Intrusion detection</h2><p>Live packet capture, flow extraction, and alert data from the existing IDS pipeline.</p></div><span className="live-indicator"><span className={`status-dot ${capture?.live ? "" : "offline"}`} />{capture?.live ? "LIVE CAPTURE" : "CAPTURE STALE"}</span></section><section className="panel workflow-panel" aria-labelledby="ids-workflow-heading"><div className="panel-heading"><div><span className="eyebrow">DETECTION FLOW</span><h3 id="ids-workflow-heading">SentinelIDS workflow</h3><p className="muted">Passive capture and alert processing remain independent from the other modules.</p></div></div><div className="workflow-stage-grid"><div className="workflow-stage"><strong>1 · Network traffic</strong><span>Authorized interface capture, when separately enabled by the operator.</span></div><div className="workflow-stage"><strong>2 · Detection</strong><span>Feature extraction, signature and anomaly detection.</span></div><div className="workflow-stage"><strong>3 · Alert processing</strong><span>Source, destination, protocol, severity, and decision evidence.</span></div><div className="workflow-stage"><strong>4 · Incident view</strong><span>Persisted alert history, summaries, and available reports.</span></div></div></section>{error && <div className="notice error"><AlertTriangle size={17} />{error}</div>}{!summary && !error ? <div className="loading"><span />Connecting to IDS telemetry...</div> : <><div className="stats-grid"><Stat label="Captured packets" value={capture?.packet_count ?? "-"} detail={capture?.live ? `Updated ${formatTime(capture.last_packet_at)}` : "No recent packet writes"} icon={Radio} tone={capture?.live ? "green" : "amber"} /><Stat label="Total alerts" value={summary?.total_alerts ?? "-"} detail="Persisted IDS alerts" icon={AlertTriangle} tone="red" /><Stat label="Critical alerts" value={summary?.critical_alerts ?? "-"} detail="Decision severity" icon={ShieldAlert} tone="amber" /><Stat label="Network scans" value={summary?.scan_count ?? "-"} detail="Recorded scan results" icon={Wifi} /></div><section className="panel live-panel"><div className="panel-heading"><div><span className="eyebrow">LIVE DETECTION FEED</span><h3>Recent network alerts</h3></div><span className="live-indicator"><span className={`status-dot ${capture?.live ? "" : "offline"}`} />{capture?.live ? "Receiving packets" : "Waiting for capture"}</span></div>{!capture?.live && <div className="notice"><Activity size={17} /><span>IDS API is connected, but the packet feature store was last updated {capture?.age_seconds == null ? "never" : `${Math.round(capture.age_seconds)} seconds ago`}.</span></div>}<div className="table-wrap"><table><thead><tr><th>Attack</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Severity</th><th>Risk</th></tr></thead><tbody>{alerts.slice(0, 20).map((alert, index) => <tr key={`${alert.timestamp}-${index}`}><td><strong>{alert.attack_name || alert.attack || "Unknown"}</strong></td><td className="mono">{alert.source_ip || "-"}</td><td className="mono">{alert.destination_ip || "-"}</td><td>{alert.protocol || "-"}</td><td><Badge level={alert.severity}>{alert.severity || "-"}</Badge></td><td>{alert.risk_score ?? "-"}</td></tr>)}</tbody></table>{!alerts.length && <p className="muted table-empty">No alerts available from the IDS service.</p>}</div></section><section className="panel"><div className="panel-heading"><div><span className="eyebrow">LAST OBSERVATION</span><h3>Capture timing</h3></div><FileSearch size={18} /></div><div className="result-meta"><span>Last packet<strong>{formatTime(capture?.last_packet_at)}</strong></span><span>Latest alert<strong>{latestAlert ? formatTime(latestAlert.timestamp) : "No alert"}</strong></span><span>Capture state<strong>{capture?.live ? "LIVE" : "STALE"}</strong></span></div></section><section className="panel report-export"><div className="panel-heading"><div><span className="eyebrow">REPORT EXPORT</span><h3>Download complete IDS report</h3><p className="muted">Includes all alerts, decisions, scans, incident reports, and summary data.</p></div><button className="download-icon-button" type="button" onClick={downloadFullReport} disabled={downloading} title="Download complete IDS report" aria-label="Download complete IDS report"><Download size={18} />{downloading ? "Preparing..." : "Download full report"}</button></div></section></>}</>;
}
