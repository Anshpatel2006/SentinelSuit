import { useEffect, useState } from "react";
import { Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bug,
  Database,
  FileText,
  Gauge,
  Globe,
  Menu,
  Shield,
  ShieldAlert,
  UploadCloud,
  Wifi,
  X,
} from "lucide-react";
import { api } from "./api";
import IDS from "./IDS";
import Phishing from "./Phishing";
import Ransomware from "./Ransomware";
import VulnScan from "./VulnScan";

const modules = [
  { path: "/vulnscan", label: "AI-VulnScan", icon: Bug, tone: "cyan" },
  { path: "/phishing", label: "Phishing Detection", icon: Globe, tone: "cyan" },
  { path: "/ransomware", label: "Ransomware Analysis", icon: UploadCloud, tone: "amber" },
  { path: "/ids", label: "SentinelIDS", icon: Wifi, tone: "red" },
];

const serviceChecks = [
  ["vulnscan", "AI-VulnScan", api.vulnscanHealth],
  ["phishing", "Phishing Detection", api.phishingHealth],
  ["ransomware", "Ransomware Analysis", api.ransomwareHealth],
  ["ids", "SentinelIDS", api.idsHealth],
];

function Shell({ children }) {
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const pageLinks = [
    ["/activity", "Scan history", Activity],
    ["/reports", "Reports", FileText],
    ["/status", "Service status", Database],
    ["/settings", "Settings", Shield],
  ];
  const title = location.pathname === "/"
    ? "Command Center"
    : modules.find((item) => location.pathname.startsWith(item.path))?.label
      || pageLinks.find(([path]) => path === location.pathname)?.[1]
      || "Security Operations";

  return (
    <div className="app-shell">
      <aside className={open ? "sidebar open" : "sidebar"}>
        <div className="brand">
          <div className="brand-mark"><Shield size={22} /></div>
          <div><strong>SENTINEL<span>SUITE</span></strong><small>Unified security operations</small></div>
          <button className="icon-button mobile-close" onClick={() => setOpen(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <nav>
          <NavLink end to="/" onClick={() => setOpen(false)}><Gauge size={18} />Command Center</NavLink>
          <p className="nav-label">Independent modules</p>
          {modules.map(({ path, label, icon: Icon, tone }) => (
            <NavLink className="module-link" to={path} key={path} onClick={() => setOpen(false)}>
              <span className={`nav-icon ${tone}`}><Icon size={16} /></span>{label}
            </NavLink>
          ))}
          <p className="nav-label">Operations</p>
          {pageLinks.map(([path, label, Icon]) => (
            <NavLink to={path} key={path} onClick={() => setOpen(false)}><Icon size={18} />{label}</NavLink>
          ))}
        </nav>
        <div className="sidebar-footer"><span className="status-dot" />Independent local services<div className="version">SENTINELSUITE / v1.0</div></div>
      </aside>
      {open && <button className="scrim" onClick={() => setOpen(false)} aria-label="Close navigation" />}
      <main className="main">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div><span className="breadcrumb">SENTINELSUITE / OPERATIONS</span><h1>{title}</h1></div>
          <div className="topbar-actions"><span className="live-indicator">LOCAL SERVICES</span><Link className="avatar" to="/status" aria-label="View service status">SS</Link></div>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  );
}

function Badge({ children, level = "info" }) {
  return <span className={`badge ${String(level).toLowerCase().replaceAll(" ", "-")}`}>{children}</span>;
}

function Stat({ label, value, detail, icon: Icon, tone = "cyan" }) {
  return <div className="stat-card"><div className={`stat-icon ${tone}`}><Icon size={19} /></div><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></div>;
}

function Notice({ children, error = false }) {
  return <div className={error ? "notice error" : "notice"}><AlertTriangle size={17} />{children}</div>;
}

function isOnline(result) {
  return result?.status === "fulfilled";
}

function valueOf(result, fallback = null) {
  return isOnline(result) ? result.value : fallback;
}

function asList(value, key) {
  if (Array.isArray(value)) return value;
  if (key && Array.isArray(value?.[key])) return value[key];
  return [];
}

function Dashboard() {
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function loadOverview() {
      const results = await Promise.allSettled([
        api.vulnscanHealth(),
        api.phishingHealth(),
        api.ransomwareHealth(),
        api.ransomwareReports(),
        api.idsHealth(),
        api.idsSummary(),
        api.idsAlerts(),
        api.vulnscanHistory(),
      ]);
      if (!active) return;
      setOverview({
        services: Object.fromEntries(serviceChecks.map(([key], index) => [key, results[index]])),
        reports: asList(valueOf(results[3]), "reports"),
        ids: valueOf(results[5]),
        alerts: asList(valueOf(results[6]), "alerts"),
        vulnScans: asList(valueOf(results[7]), "scans"),
      });
      setLoading(false);
    }
    loadOverview();
    return () => { active = false; };
  }, []);

  const serviceCount = overview
    ? serviceChecks.filter(([key]) => isOnline(overview.services[key])).length
    : 0;
  const reportCount = overview?.reports.length || 0;
  const scanCount = Number(overview?.ids?.scan_count || 0) + (overview?.vulnScans.length || 0);
  const detected = (overview?.reports || []).filter((item) => String(item.risk_level || "").toLowerCase() !== "low").length
    + (overview?.alerts.length || 0);

  return (
    <>
      <section className="hero">
        <div><span className="eyebrow">UNIFIED THREAT OPERATIONS</span><h2>See the whole security picture.</h2><p>Four independent analysis modules, each connected to its own service and workflow.</p></div>
        <div className="hero-signal"><span className="pulse" /><span>{loading ? "CHECKING SERVICES" : `${serviceCount} OF 4 SERVICES ONLINE`}</span><small>Opening a module never starts a scan</small></div>
      </section>
      <div className="stats-grid">
        <Stat label="File reports" value={loading ? "—" : reportCount} detail="Ransomware analysis service" icon={BarChart3} />
        <Stat label="IDS alerts" value={loading ? "—" : overview?.alerts.length || 0} detail="Persisted network events" icon={ShieldAlert} tone="red" />
        <Stat label="Recorded detections" value={loading ? "—" : detected} detail="Existing reports and alerts" icon={AlertTriangle} tone="amber" />
        <Stat label="Services online" value={loading ? "—" : `${serviceCount}/4`} detail="Independent health checks" icon={Activity} tone={serviceCount === 4 ? "green" : "amber"} />
      </div>
      <section className="section-heading"><div><span className="eyebrow">SECURITY MODULES</span><h3>Choose an independent module</h3></div></section>
      <div className="module-grid module-grid-four">
        {modules.map(({ path, label, icon: Icon, tone }, index) => (
          <Link className="module-card" to={path} key={path}>
            <div className={`module-art ${tone}`}><Icon size={26} /></div>
            <div><span className="module-index">0{index + 1}</span><h3>{label}</h3><p>{[
              "Authorized Nmap scans, evidence-based findings, and remediation.",
              "URL features, rule analysis, ML, and available threat intelligence.",
              "File hashing, static analysis, optional sandbox, and reports.",
              "Independent network telemetry, alerts, and incident summaries.",
            ][index]}</p></div>
            <span className="arrow" aria-hidden="true">→</span>
          </Link>
        ))}
      </div>
      <section className="panel service-panel">
        <div className="panel-heading"><div><span className="eyebrow">PLATFORM STATUS</span><h3>Connected services</h3></div><Link to="/status">Details</Link></div>
        {serviceChecks.map(([key, label]) => {
          const result = overview?.services[key];
          const online = isOnline(result);
          return <div className="service-row" key={key}><span className={`status-dot ${online ? "" : "offline"}`} /><span>{label}</span><small>{loading ? "Checking" : online ? "Online" : "Unavailable"}</small></div>;
        })}
        {!loading && serviceCount < 4 && <p className="muted">A disconnected service does not block the other modules.</p>}
      </section>
      <p className="dashboard-footnote">{scanCount} network or vulnerability scans recorded. Phishing scan history is not persisted by its current backend.</p>
    </>
  );
}

function ActivityPage() {
  const [records, setRecords] = useState(null);
  const [errors, setErrors] = useState({});

  useEffect(() => {
    let active = true;
    Promise.allSettled([api.ransomwareReports(), api.ransomwareJobs(), api.idsAlerts(), api.vulnscanHistory()])
      .then((results) => {
        if (!active) return;
        setRecords({
          ransomware: asList(valueOf(results[0]), "reports"),
          jobs: asList(valueOf(results[1]), "jobs"),
          alerts: asList(valueOf(results[2]), "alerts"),
          scans: asList(valueOf(results[3]), "scans"),
        });
        setErrors(Object.fromEntries(results.flatMap((result, index) => result.status === "rejected"
          ? [[["ransomware reports", "ransomware jobs", "IDS alerts", "vulnerability scan history"][index], result.reason?.message || "Service unavailable"]]
          : [])));
      });
    return () => { active = false; };
  }, []);

  if (!records) return <div className="loading"><span />Loading available scan history...</div>;
  return (
    <>
      <section className="page-intro"><div><span className="eyebrow">OPERATIONS / HISTORY</span><h2>Scan history</h2><p>History comes from each module’s own backend. A failed service leaves the remaining history available.</p></div></section>
      {Object.entries(errors).map(([name, error]) => <Notice error key={name}>{name}: {error}</Notice>)}
      <HistoryTable title="AI-VulnScan" rows={records.scans} idKey="scan_id" nameKey="target" riskKey="risk_level" />
      <HistoryTable title="Ransomware analysis" rows={records.ransomware} idKey="sample_id" nameKey="filename" riskKey="risk_level" />
      <HistoryTable title="SentinelIDS alerts" rows={records.alerts} idKey="timestamp" nameKey="attack_name" riskKey="severity" />
      <section className="panel"><div className="panel-heading"><h3>Phishing URL scans</h3><Badge level="warning">NOT PERSISTED</Badge></div><p className="muted">The current phishing API returns scan results but does not expose a history store. Results are not fabricated or retained as server history.</p></section>
      <section className="panel"><div className="panel-heading"><h3>Ransomware jobs</h3><span>{records.jobs.length} records</span></div>{records.jobs.slice(0, 12).map((job) => <div className="activity-row" key={job.job_id}><span className="activity-marker cyan" /><div><strong>{job.filename || job.job_id}</strong><small>{job.current_stage || job.job_id}</small></div><Badge level={job.status}>{job.status}</Badge></div>)}{!records.jobs.length && <p className="muted">No jobs are currently returned.</p>}</section>
    </>
  );
}

function HistoryTable({ title, rows, idKey, nameKey, riskKey }) {
  return (
    <section className="panel">
      <div className="panel-heading"><h3>{title}</h3><span>{rows.length} records</span></div>
      <div className="table-wrap"><table><thead><tr><th>Identifier</th><th>Target / name</th><th>Severity</th></tr></thead><tbody>
        {rows.slice(0, 30).map((item, index) => <tr key={`${item[idKey] || "record"}-${index}`}><td className="mono">{item[idKey] || "—"}</td><td>{item[nameKey] || item.attack || item.url || "—"}</td><td><Badge level={item[riskKey] || "info"}>{item[riskKey] || "—"}</Badge></td></tr>)}
      </tbody></table>{!rows.length && <p className="muted table-empty">No records are currently available.</p>}</div>
    </section>
  );
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [scans, setScans] = useState([]);
  const [errors, setErrors] = useState([]);
  const [busy, setBusy] = useState("");

  useEffect(() => {
    let active = true;
    Promise.allSettled([api.ransomwareReports(), api.vulnscanHistory()])
      .then(([malware, vulnerability]) => {
        if (!active) return;
        setReports(asList(valueOf(malware), "reports"));
        setScans(asList(valueOf(vulnerability), "scans"));
        setErrors([malware, vulnerability].flatMap((result, index) => result.status === "rejected"
          ? [[index === 0 ? "Ransomware reports" : "AI-VulnScan reports", result.reason?.message || "Service unavailable"]]
          : []));
      });
    return () => { active = false; };
  }, []);

  async function downloadRansomware(sampleId) {
    setBusy(sampleId);
    try {
      const response = await api.ransomwareReportPdf(sampleId);
      saveBlob(await response.blob(), `${sampleId}.pdf`);
    } catch (error) {
      setErrors((current) => [...current, ["Ransomware report", error.message]]);
    } finally {
      setBusy("");
    }
  }

  async function downloadVulnerability(scanId) {
    setBusy(scanId);
    try {
      const response = await api.vulnscanReport(scanId);
      saveBlob(await response.blob(), `${scanId}-report`);
    } catch (error) {
      setErrors((current) => [...current, ["AI-VulnScan report", error.message]]);
    } finally {
      setBusy("");
    }
  }

  async function downloadIdsReport() {
    setBusy("ids");
    try {
      const report = await api.idsFullReport();
      saveBlob(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }), "sentinelids-report.json");
    } catch (error) {
      setErrors((current) => [...current, ["SentinelIDS report", error.message]]);
    } finally {
      setBusy("");
    }
  }

  return (
    <>
      <section className="page-intro"><div><span className="eyebrow">OPERATIONS / EXPORTS</span><h2>Reports</h2><p>Download reports from the module that generated them; no shared report store is assumed.</p></div></section>
      {errors.map(([name, error], index) => <Notice error key={`${name}-${index}`}>{name}: {error}</Notice>)}
      <section className="panel"><div className="panel-heading"><div><h3>Ransomware reports</h3><p className="muted">Generated PDF reports from the malware-analysis backend.</p></div></div>
        {reports.map((report) => <div className="activity-row" key={report.sample_id}><span className="activity-marker amber" /><div><strong>{report.filename || report.sample_id}</strong><small>{report.branch || "Analysis report"} · {report.risk_level || "Risk unavailable"}</small></div><button className="button secondary" disabled={busy === report.sample_id} onClick={() => downloadRansomware(report.sample_id)}>{busy === report.sample_id ? "Preparing..." : "Download PDF"}</button></div>)}
        {!reports.length && <p className="muted">No ransomware reports are available.</p>}
      </section>
      <section className="panel"><div className="panel-heading"><div><h3>AI-VulnScan reports</h3><p className="muted">Reports available from completed scanner history.</p></div></div>
        {scans.map((scan, index) => {
          const scanId = scan.scan_id || scan.id;
          return <div className="activity-row" key={scanId || index}><span className="activity-marker cyan" /><div><strong>{scan.target || scanId || "Completed scan"}</strong><small>{scan.status || "Recorded scan"}</small></div><button className="button secondary" disabled={!scanId || busy === scanId} onClick={() => downloadVulnerability(scanId)}>{busy === scanId ? "Preparing..." : "Download report"}</button></div>;
        })}
        {!scans.length && <p className="muted">No vulnerability scan reports are available.</p>}
      </section>
      <section className="panel"><div className="panel-heading"><div><h3>SentinelIDS report</h3><p className="muted">Export the backend’s current alerts, decisions, scans, incident reports, and summary as JSON.</p></div><button className="button secondary" disabled={busy === "ids"} onClick={downloadIdsReport}>{busy === "ids" ? "Preparing..." : "Download IDS report"}</button></div></section>
      <section className="panel"><div className="panel-heading"><h3>Phishing reports</h3><Badge level="warning">ON-DEMAND</Badge></div><p className="muted">The phishing service generates a PDF for the active scan result. Generate it from the Phishing Detection page; it does not provide a historical report list.</p></section>
    </>
  );
}

function ServiceStatus() {
  const [services, setServices] = useState(null);
  useEffect(() => {
    let active = true;
    Promise.allSettled(serviceChecks.map(([, , check]) => check()))
      .then((results) => {
        if (active) setServices(Object.fromEntries(serviceChecks.map(([key], index) => [key, results[index]])));
      });
    return () => { active = false; };
  }, []);
  return (
    <>
      <section className="page-intro"><div><span className="eyebrow">CONFIGURATION / HEALTH</span><h2>Service status</h2><p>Each health check is independent and uses that module’s own API.</p></div></section>
      <div className="status-grid">{serviceChecks.map(([key, label]) => {
        const result = services?.[key];
        const online = isOnline(result);
        return <div className="status-card" key={key}><span className={`status-dot ${online ? "" : "offline"}`} /><div><h3>{label}</h3><p>{!result ? "Checking connection..." : online ? "Online and responding" : result.reason?.message || "Service unavailable"}</p></div><Badge level={!result ? "pending" : online ? "safe" : "warning"}>{!result ? "Checking" : online ? "Online" : "Offline"}</Badge></div>;
      })}</div>
    </>
  );
}

function Settings() {
  return (
    <>
      <section className="page-intro"><div><span className="eyebrow">CONFIGURATION</span><h2>Settings</h2><p>Service addresses are configurable at build time. Credentials remain server-side.</p></div></section>
      <section className="panel"><div className="panel-heading"><h3>Backend endpoints</h3></div>
        {serviceChecks.map(([key, label]) => <div className="service-row" key={key}><span className="status-dot" /><span>{label}</span><code>{api.services[key]}</code></div>)}
      </section>
      <Notice>Only scan targets and files you are explicitly authorized to assess. IDS packet capture and active follow-up scans require separate operator authorization.</Notice>
    </>
  );
}

export default function App() {
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/vulnscan" element={<VulnScan />} />
        <Route path="/phishing" element={<Phishing />} />
        <Route path="/ransomware" element={<Ransomware />} />
        <Route path="/ids" element={<IDS />} />
        <Route path="/activity" element={<ActivityPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/status" element={<ServiceStatus />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Dashboard />} />
      </Routes>
    </Shell>
  );
}
