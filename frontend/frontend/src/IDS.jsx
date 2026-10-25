import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Download,
  FileSearch,
  Play,
  Radio,
  ShieldAlert,
  Square,
  Wifi,
} from "lucide-react";
import { api } from "./api";
import "./ids.css";
import "./workflow.css";

function SeverityBadge({ level }) {
  const severity = String(level || "info").toLowerCase();
  return <span className={`badge ${severity}`}>{level || "-"}</span>;
}

function StatCard({ label, value, detail, icon: Icon, tone = "cyan" }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}>
        <Icon size={19} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </div>
  );
}

function formatTime(timestamp) {
  if (!timestamp) return "No packet recorded";
  const date = typeof timestamp === "number"
    ? new Date(timestamp * 1000)
    : new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleTimeString();
}

export default function IDS() {
  const [summary, setSummary] = useState(null);
  const [capture, setCapture] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [toggling, setToggling] = useState(false);

  async function fetchTelemetry(isActive = () => true) {
    const results = await Promise.allSettled([
      api.idsSummary(),
      api.idsAlerts(),
      api.idsCaptureStatus(),
    ]);
    if (!isActive()) return;
    const [summaryResult, alertsResult, captureResult] = results;

    if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
    if (alertsResult.status === "fulfilled") {
      setAlerts(Array.isArray(alertsResult.value) ? alertsResult.value : []);
    }
    if (captureResult.status === "fulfilled") setCapture(captureResult.value);

    const failures = results
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason?.message || "IDS telemetry request failed");
    setError(failures.join(" | "));
  }

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      await fetchTelemetry(() => active);
    };

    refresh();
    const interval = setInterval(refresh, 2500);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  async function toggleCapture() {
    setToggling(true);
    try {
      await api.idsToggleCapture();
      await fetchTelemetry();
    } catch (toggleError) {
      setError(`Failed to toggle packet capture: ${toggleError.message}`);
    } finally {
      setToggling(false);
    }
  }

  async function downloadPdfReport() {
    setDownloading(true);
    try {
      const response = await api.idsPdfReport();
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `SentinelIDS-Incident-Report-${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (downloadError) {
      setError(downloadError.message);
    } finally {
      setDownloading(false);
    }
  }

  const latestAlert = alerts[0];

  return (
    <>
      <section className="page-intro">
        <div>
          <span className="eyebrow">NETWORK TELEMETRY / IDS SERVICE</span>
          <h2>Intrusion detection</h2>
          <p>Live packet capture, flow extraction, and alert data from the existing IDS pipeline.</p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <span className="live-indicator">
            <span className={`status-dot ${capture?.live ? "" : "offline"}`} />
            {capture?.live ? "LIVE CAPTURE" : "CAPTURE STALE"}
          </span>
          <button
            className="download-icon-button"
            type="button"
            onClick={toggleCapture}
            disabled={toggling}
          >
            {capture?.live ? <Square size={14} /> : <Play size={14} />}
            {toggling ? "Updating..." : capture?.live ? "Stop Live Capture" : "Start Live Capture"}
          </button>
        </div>
      </section>

      {error && (
        <div className="notice error">
          <AlertTriangle size={17} />
          {error}
        </div>
      )}
      {capture?.status?.startsWith("ERROR") && (
        <div className="notice error">
          <AlertTriangle size={17} />
          Packet capture failed: {capture.status}
        </div>
      )}

      {!summary && !error ? (
        <div className="loading">
          <span />
          Connecting to IDS telemetry...
        </div>
      ) : (
        <>
          <div className="stats-grid">
            <StatCard
              label="Captured packets"
              value={capture?.packet_count ?? "-"}
              detail={capture?.live ? `Updated ${formatTime(capture.last_packet_at)}` : "No recent packet writes"}
              icon={Radio}
              tone={capture?.live ? "green" : "amber"}
            />
            <StatCard
              label="Total alerts"
              value={summary?.total_alerts ?? "-"}
              detail="Persisted IDS alerts"
              icon={AlertTriangle}
              tone="red"
            />
            <StatCard
              label="Critical alerts"
              value={summary?.critical_alerts ?? "-"}
              detail="Decision severity"
              icon={ShieldAlert}
              tone="amber"
            />
            <StatCard
              label="Network scans"
              value={summary?.scan_count ?? "-"}
              detail="Recorded scan results"
              icon={Wifi}
            />
          </div>

          <section className="panel live-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">LIVE DETECTION FEED</span>
                <h3>Recent network alerts</h3>
              </div>
              <span className="live-indicator">
                <span className={`status-dot ${capture?.live ? "" : "offline"}`} />
                {capture?.live ? "Receiving packets" : "Waiting for capture"}
              </span>
            </div>

            {!capture?.live && !capture?.status?.startsWith("ERROR") && (
              <div className="notice">
                <Activity size={17} />
                <span>
                IDS API is connected, but live capture is currently idle. Click &quot;Start Live Capture&quot; above to begin monitoring on the default network interface.
                </span>
              </div>
            )}

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Attack</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Severity</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 20).map((alert, index) => (
                    <tr key={`${alert.timestamp}-${index}`}>
                      <td><strong>{alert.attack_name || alert.attack || "Unknown"}</strong></td>
                      <td className="mono">{alert.source_ip || "-"}</td>
                      <td className="mono">{alert.destination_ip || "-"}</td>
                      <td>{alert.protocol || "-"}</td>
                      <td><SeverityBadge level={alert.severity} /></td>
                      <td>{alert.risk_score ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {!alerts.length && (
                <p className="muted table-empty">No alerts available from the IDS service.</p>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">LAST OBSERVATION</span>
                <h3>Capture timing</h3>
              </div>
              <FileSearch size={18} />
            </div>
            <div className="result-meta">
              <span>Last packet<strong>{formatTime(capture?.last_packet_at)}</strong></span>
              <span>Latest alert<strong>{latestAlert ? formatTime(latestAlert.timestamp) : "No alert"}</strong></span>
              <span>Capture state<strong>{capture?.live ? "LIVE" : "STALE"}</strong></span>
            </div>
          </section>

          <section className="panel report-export">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">REPORT EXPORT</span>
                <h3>Download complete IDS report (PDF)</h3>
                <p className="muted">
                  Includes alerts, decisions, scans, incident reports, and summary data compiled into a PDF.
                </p>
              </div>
              <button
                className="download-icon-button"
                type="button"
                onClick={downloadPdfReport}
                disabled={downloading}
                title="Download complete IDS PDF report"
                aria-label="Download complete IDS PDF report"
              >
                <Download size={18} />
                {downloading ? "Generating PDF..." : "Download PDF report"}
              </button>
            </div>
          </section>
        </>
      )}
    </>
  );
}
