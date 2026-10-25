import { useState, useEffect } from "react";
import { AlertTriangle, Radio, ShieldAlert, Wifi, Activity, FileSearch, Download, Play, Square } from "lucide-react";

const IDS_API_URL = import.meta.env.VITE_IDS_API_URL || "http://127.0.0.1:8002";

function formatTime(timestamp) {
  if (!timestamp) return "No packet recorded";
  const date = typeof timestamp === "number" ? new Date(timestamp * 1000) : new Date(timestamp);
  return isNaN(date.getTime()) ? "Unknown time" : date.toLocaleTimeString();
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

function SeverityBadge({ level }) {
  const lvl = String(level || "info").toLowerCase();
  return <span className={`badge ${lvl}`}>{level || "-"}</span>;
}

export default function IDS() {
  const [summary, setSummary] = useState(null);
  const [capture, setCapture] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [toggling, setToggling] = useState(false);

  // Fetch telemetry from backend
  async function fetchTelemetry() {
    try {
      const [sumRes, alertRes, capRes] = await Promise.all([
        fetch(`${IDS_API_URL}/dashboard/summary`).then((r) => r.json()).catch(() => null),
        fetch(`${IDS_API_URL}/dashboard/recent-alerts`).then((r) => r.json()).catch(() => []),
        fetch(`${IDS_API_URL}/dashboard/capture-status`).then((r) => r.json()).catch(() => null)
      ]);

      if (sumRes) setSummary(sumRes);
      if (Array.isArray(alertRes)) setAlerts(alertRes);
      if (capRes) setCapture(capRes);
      setError("");
    } catch (err) {
      setError(err.message || "Failed to connect to IDS telemetry");
    }
  }

  useEffect(() => {
    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 2500);
    return () => clearInterval(interval);
  }, []);

  // Toggle Live Packet Capture On / Off
  async function toggleCapture() {
    setToggling(true);
    try {
      const res = await fetch(`${IDS_API_URL}/dashboard/capture/toggle`, { method: "POST" });
      const data = await res.json();
      setCapture((prev) => ({ ...prev, live: data.live }));
      await fetchTelemetry();
    } catch (err) {
      setError("Failed to toggle packet capture: " + err.message);
    } finally {
      setToggling(false);
    }
  }

  // Download Official PDF Report
  async function downloadPdfReport() {
    setDownloading(true);
    try {
      const response = await fetch(`${IDS_API_URL}/dashboard/full-report/pdf`);
      if (!response.ok) throw new Error("Failed to generate PDF report from server.");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `SentinelIDS-Incident-Report-${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message);
    } finally {
      setDownloading(false);
    }
  }

  const latestAlert = alerts[0];

  return (
    <>
      {/* Page Header with Live Sniffing Indicator and Start/Stop Button */}
      <section className="page-intro">
        <div>
          <span className="eyebrow">NETWORK TELEMETRY / IDS SERVICE</span>
          <h2>Intrusion detection</h2>
          <p>Live packet capture, flow extraction, and alert data from the existing IDS pipeline.</p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span className="live-indicator">
            <span className={`status-dot ${capture?.live ? "" : "offline"}`} />
            {capture?.live ? "LIVE CAPTURE" : "CAPTURE STALE"}
          </span>

          {/* Live Capture Enable / Disable Button */}
          <button
            type="button"
            className={`button ${capture?.live ? "danger" : "primary"}`}
            onClick={toggleCapture}
            disabled={toggling}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              padding: "7px 14px",
              fontSize: "12px",
              cursor: "pointer",
              borderRadius: "6px"
            }}
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

      {!summary && !error ? (
        <div className="loading">
          <span />
          Connecting to IDS telemetry...
        </div>
      ) : (
        <>
          {/* Top 4 Metrics Cards */}
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

          {/* Live Threat Detection Feed */}
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

            {!capture?.live && (
              <div className="notice">
                <Activity size={17} />
                <span>
                  IDS API is connected, but live capture is currently idle. Click &quot;Start Live Capture&quot; above to begin monitoring.
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
                      <td>
                        <strong>{alert.attack_name || alert.attack || "Unknown"}</strong>
                      </td>
                      <td className="mono">{alert.source_ip || "-"}</td>
                      <td className="mono">{alert.destination_ip || "-"}</td>
                      <td>{alert.protocol || "-"}</td>
                      <td>
                        <SeverityBadge level={alert.severity} />
                      </td>
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

          {/* Last Observation Timing */}
          <section className="panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">LAST OBSERVATION</span>
                <h3>Capture timing</h3>
              </div>
              <FileSearch size={18} />
            </div>
            <div className="result-meta">
              <span>
                Last packet<strong>{formatTime(capture?.last_packet_at)}</strong>
              </span>
              <span>
                Latest alert<strong>{latestAlert ? formatTime(latestAlert.timestamp) : "No alert"}</strong>
              </span>
              <span>
                Capture state<strong>{capture?.live ? "LIVE" : "STALE"}</strong>
              </span>
            </div>
          </section>

          {/* Official PDF Report Export */}
          <section className="panel report-export">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">REPORT EXPORT</span>
                <h3>Download complete IDS report (PDF)</h3>
                <p className="muted">
                  Includes all alerts, decisions, scans, incident reports, and summary data compiled into an official PDF document.
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
