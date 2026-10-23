import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Bug, Download, Search, ShieldCheck } from "lucide-react";
import { api } from "./api";
import "./workflow.css";

const terminalStatuses = new Set(["completed", "partial", "failed"]);

function asList(value, key = "scans") {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.[key])) return value[key];
  return [];
}

function messageOf(error) {
  return error instanceof Error ? error.message : "AI-VulnScan request failed.";
}

function versionMatchedCves(service) {
  return Array.isArray(service?.cve_candidates)
    ? service.cve_candidates.filter((cve) => cve?.match_status === "version_match")
    : [];
}

function Notice({ children, error = false }) {
  return <div className={error ? "notice error" : "notice"}><AlertTriangle size={17} />{children}</div>;
}

function Workflow() {
  return (
    <section className="panel workflow-panel" aria-labelledby="vuln-workflow-heading">
      <div className="panel-heading"><div><span className="eyebrow">SCAN FLOW</span><h3 id="vuln-workflow-heading">AI-VulnScan workflow</h3><p className="muted">Findings require supporting evidence; an open port alone is not a vulnerability.</p></div></div>
      <div className="workflow-stage-grid">
        <div className="workflow-stage"><strong>1 · Authorized target</strong><span>Enter a permitted IP, hostname, or bounded CIDR; confirm scope explicitly.</span></div>
        <div className="workflow-stage"><strong>2 · Nmap scan</strong><span>Choose an available profile and inspect discovered ports and services.</span></div>
        <div className="workflow-stage"><strong>3 · Evidence analysis</strong><span>Rules and available CVE data produce evidence-based, non-confirmatory findings.</span></div>
        <div className="workflow-stage"><strong>4 · Risk and remediation</strong><span>Review actual severity, explainability, recommendations, and generated reports.</span></div>
      </div>
    </section>
  );
}

function ServiceRows({ rows }) {
  if (!Array.isArray(rows) || !rows.length) return null;
  return (
    <section className="panel">
      <div className="panel-heading"><h3>Discovered ports and services</h3><span>{rows.length} records</span></div>
      <p className="muted">CVE matches below are limited to NVD records whose CPE and affected-version range match the detected service version. A match is not proof of exploitability.</p>
      <div className="table-wrap"><table><thead><tr>
        <th>Host</th><th>Hostnames</th><th>Port</th><th>Protocol</th><th>State</th>
        <th>Service</th><th>Product</th><th>Version</th><th>Version-matched CVEs</th>
      </tr></thead>
        <tbody>{rows.slice(0, 100).map((row, index) => {
          const matchedCves = versionMatchedCves(row);
          return <tr key={`${row.host || ""}:${row.port || index}:${row.protocol || ""}`}>
            <td>{row.host || "—"}</td>
            <td>{Array.isArray(row.hostnames) ? row.hostnames.join(", ") || "—" : row.hostnames || "—"}</td>
            <td>{row.port ?? "—"}</td>
            <td>{row.protocol || "—"}</td>
            <td>{row.state || "unknown"}</td>
            <td>{row.service || "Not detected"}</td>
            <td>{row.product || "Not detected"}</td>
            <td>{row.version || "Not detected"}</td>
            <td>{matchedCves.length
              ? matchedCves.map((cve) => <div key={cve.id}>
                <a href={cve.url || `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`} target="_blank" rel="noreferrer">{cve.id}</a>
                {cve.cvss_score != null ? ` (CVSS ${cve.cvss_score})` : ""}
              </div>)
              : "No version-matched CVE"}</td>
          </tr>;
        })}</tbody>
      </table></div>
    </section>
  );
}

function Summary({ value }) {
  if (value == null || typeof value !== "object") return null;
  const entries = Object.entries(value).filter(([, item]) => item == null || ["string", "number", "boolean"].includes(typeof item));
  if (!entries.length) return null;
  return <div className="stats-grid compact">{entries.slice(0, 8).map(([key, item]) => <div className="stat-card" key={key}><div><span>{key.replaceAll("_", " ")}</span><strong>{String(item ?? "—")}</strong></div></div>)}</div>;
}

function Findings({ items }) {
  if (!items.length) return <p className="muted">No finding records were returned for this scan.</p>;
  return <div className="vuln-findings">{items.map((finding, index) => (
    <article className="vuln-finding" key={finding.id || finding.cve_id || index}>
      <div className="vuln-finding-heading"><strong>{finding.title || finding.name || finding.cve_id || finding.rule_id || "Finding"}</strong><span className={`badge ${String(finding.severity || finding.risk_level || "info").toLowerCase()}`}>{finding.severity || finding.risk_level || "Unrated"}</span></div>
      {finding.description && <p>{finding.description}</p>}
      {finding.explanation && <p>{typeof finding.explanation === "string" ? finding.explanation : JSON.stringify(finding.explanation)}</p>}
      {(finding.score != null || finding.cvss != null) && <p className="muted">Score: {finding.score ?? finding.cvss}</p>}
      {finding.evidence && <details><summary>Evidence</summary><pre>{typeof finding.evidence === "string" ? finding.evidence : JSON.stringify(finding.evidence, null, 2)}</pre></details>}
      {finding.recommendation && <p className="muted"><strong>Recommendation:</strong> {finding.recommendation}</p>}
    </article>
  ))}</div>;
}

function RiskAssessments({ items, services, findings, recommendations }) {
  if (!items.length) return null;
  return (
    <section className="panel">
      <div className="panel-heading"><h3>Risk assessments</h3><span>{items.length} records</span></div>
      <div className="vuln-findings">{items.map((assessment, index) => {
        const findingId = String(assessment.finding_id || "");
        const cveId = findingId.match(/^CVE-\d{4}-\d+/i)?.[0];
        const service = services.find((item) =>
          item.host === assessment.host && item.port === assessment.port,
        );
        const cve = cveId && Array.isArray(service?.cve_candidates)
          ? service.cve_candidates.find((item) =>
            item.id === cveId && item.match_status === "version_match",
          )
          : null;
        const finding = findings.find((item) => item.finding_id === findingId);
        const risk = assessment.risk && typeof assessment.risk === "object"
          ? assessment.risk
          : {};
        const recommendation = recommendations.find((item) =>
          cve
            ? String(item.problem || "").includes(cve.id)
            : item.problem === finding?.name,
        );
        const factors = Array.isArray(risk.factors) ? risk.factors : [];
        const steps = Array.isArray(recommendation?.verification_steps)
          ? recommendation.verification_steps
          : [];
        const refs = Array.isArray(cve?.references) ? cve.references : [];

        return (
          <article className="vuln-finding" key={findingId || index}>
            <div className="vuln-finding-heading">
              <strong>{cve?.id || assessment.name || finding?.name || "Risk finding"}</strong>
              <span className={`badge ${String(risk.category || "Informational").toLowerCase()}`}>
                {risk.category || "Informational"} · {risk.score ?? 0}/100
              </span>
            </div>
            <p>
              <strong>Detected:</strong>{" "}
              {[
                service?.service || assessment.service,
                service?.product || assessment.product,
                service?.version || assessment.version,
              ].filter(Boolean).join(" ") || "Service or version was not identified"}
              {" · "}{assessment.host || "Unknown host"}:{assessment.port ?? "unknown port"}
            </p>

            {cve ? <>
              <p>
                <strong>Matched CVE:</strong>{" "}
                <a href={cve.url || `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`} target="_blank" rel="noreferrer">{cve.id}</a>
                {" · NVD CVSS: "}{cve.cvss_score ?? "not provided"}
                {" · NVD severity: "}{cve.severity || "Unknown"}
              </p>
              <p><strong>Why it matters:</strong> {cve.description || "NVD does not provide an English description for this record."}</p>
              <p><strong>Version applicability:</strong> NVD CPE identity and affected-version range matched the detected version ({service?.version || cve.evidence?.version || "version unavailable"}). This is a candidate match, not proof that the vulnerable condition is exploitable or that vendor backports are absent.</p>
              <p><strong>Why this risk level:</strong> The deterministic project score is {risk.score ?? 0}/100 ({risk.category || "Informational"}). It combines NVD CVSS, evidence confidence, and applicability; it is distinct from NVD's CVSS rating. A CVSS Critical rating describes potential vulnerability severity, not confirmed compromise of this host.</p>
            </> : <>
              {finding?.description && <p><strong>Observed issue:</strong> {finding.description}</p>}
              <p><strong>Why this risk level:</strong> {risk.reasoning || "This score is based on the available rule and scan evidence."}</p>
              <p className="muted">No CPE-and-version-matched CVE was established for this assessment.</p>
            </>}

            <p><strong>Recovery / remediation:</strong>{" "}
              {recommendation?.action
                || "Confirm the product and installed build with its owner, consult the official vendor advisory, and apply a vendor-supported fix only after verifying applicability."}
            </p>
            {steps.length > 0 && <p><strong>Verify recovery:</strong> {steps.join(" ")}</p>}
            {recommendation?.operational_impact && <p className="muted"><strong>Operational impact:</strong> {recommendation.operational_impact}</p>}
            {refs.length > 0 && <p><strong>References:</strong>{" "}{refs.slice(0, 4).map((url, refIndex) => <a key={`${url}-${refIndex}`} href={url} target="_blank" rel="noreferrer">{refIndex ? " · " : ""}{refIndex + 1}</a>)}</p>}
            {factors.length > 0 && <details><summary>Risk scoring factors</summary><pre>{JSON.stringify(factors, null, 2)}</pre></details>}
          </article>
        );
      })}</div>
    </section>
  );
}

function scanIdentifier(scan) {
  return scan?.scan_id || scan?.id || "";
}

export default function VulnScan() {
  const [health, setHealth] = useState(null);
  const [profiles, setProfiles] = useState([]);
  const [history, setHistory] = useState([]);
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("standard");
  const [authorized, setAuthorized] = useState(false);
  const [confirmScope, setConfirmScope] = useState(false);
  const [confirmComprehensive, setConfirmComprehensive] = useState(false);
  const [confirmAggressive, setConfirmAggressive] = useState(false);
  const [confirmAllPorts, setConfirmAllPorts] = useState(false);
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [historyError, setHistoryError] = useState("");
  const [reportLoading, setReportLoading] = useState(false);

  const refreshHistory = useCallback(async () => {
    try {
      setHistory(asList(await api.vulnscanHistory()));
      setHistoryError("");
    } catch (historyFailure) {
      setHistoryError(messageOf(historyFailure));
    }
  }, []);

  useEffect(() => {
    let active = true;
    Promise.allSettled([api.vulnscanHealth(), api.vulnscanProfiles(), api.vulnscanHistory()])
      .then(([healthResult, profileResult, historyResult]) => {
        if (!active) return;
        setHealth(healthResult.status === "fulfilled" ? healthResult.value : null);
        if (profileResult.status === "fulfilled") {
          const list = asList(profileResult.value, "profiles");
          setProfiles(list);
          if (list.length && !list.some((item) => (item.id || item) === profile)) {
            setProfile(item => list.some((profileItem) => (profileItem.id || profileItem) === item)
              ? item
              : list[0].id || list[0]);
          }
        } else {
          setError(messageOf(profileResult.reason));
        }
        if (historyResult.status === "fulfilled") {
          setHistory(asList(historyResult.value));
        } else {
          setHistoryError(messageOf(historyResult.reason));
        }
        if (healthResult.status === "rejected" && profileResult.status === "rejected") {
          setError(messageOf(healthResult.reason));
        }
      });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const id = scanIdentifier(scan);
    if (!id || terminalStatuses.has(String(scan?.status).toLowerCase())) return undefined;
    let active = true;
    const poll = async () => {
      try {
        const updated = await api.vulnscanGet(id);
        if (active) {
          setScan(updated);
          if (terminalStatuses.has(String(updated.status).toLowerCase())) refreshHistory();
        }
      } catch (pollError) {
        if (active) setError(messageOf(pollError));
      }
    };
    const timer = setInterval(poll, 2000);
    return () => { active = false; clearInterval(timer); };
  }, [scan?.scan_id, scan?.id, scan?.status, refreshHistory]);

  const isCidr = target.includes("/");
  const comprehensive = profile === "comprehensive";
  const aggressive = profile === "aggressive";
  const allTcpUdp = profile === "all_tcp_udp";
  const canSubmit = health && profiles.length > 0 && target.trim() && authorized
    && (!isCidr || confirmScope) && (!comprehensive || confirmComprehensive)
    && (!aggressive || confirmAggressive) && (!allTcpUdp || confirmAllPorts) && !loading;

  async function submit(event) {
    event.preventDefault();
    setError("");
    setScan(null);
    setLoading(true);
    try {
      const submitted = await api.vulnscanSubmit({
        target: target.trim(),
        profile,
        authorized,
        ...(isCidr ? { confirm_multiple_hosts: confirmScope } : {}),
        ...(comprehensive ? { confirm_comprehensive: confirmComprehensive } : {}),
        ...(aggressive ? { confirm_aggressive: confirmAggressive } : {}),
        ...(allTcpUdp ? { confirm_all_ports: confirmAllPorts } : {}),
      });
      setScan(submitted);
      refreshHistory();
    } catch (submitError) {
      setError(messageOf(submitError));
    } finally {
      setLoading(false);
    }
  }

  async function downloadReport(format) {
    const id = scanIdentifier(scan);
    if (!id) return;
    setReportLoading(true);
    setError("");
    try {
      const response = await api.vulnscanReport(id, format);
      const fileUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = fileUrl;
      link.download = `${id}-report.${format}`;
      link.click();
      URL.revokeObjectURL(fileUrl);
    } catch (reportError) {
      setError(messageOf(reportError));
    } finally {
      setReportLoading(false);
    }
  }

  async function openHistory(scanId) {
    setError("");
    try {
      setScan(await api.vulnscanGet(scanId));
    } catch (historyFailure) {
      setError(messageOf(historyFailure));
    }
  }

  const result = scan?.result;
  const findingData = result?.findings || result?.analysis?.findings;
  const findings = Array.isArray(findingData) ? findingData : [];
  const serviceData = result?.services || result?.hosts?.flatMap((host) => host.services || host.ports || []);
  const services = Array.isArray(serviceData) ? serviceData : [];
  const riskAssessments = (Array.isArray(result?.risk_assessments) ? result.risk_assessments : [])
    .filter((assessment) => {
      if (!String(assessment?.finding_id || "").startsWith("CVE-")) return true;
      return services.some((service) =>
        service.host === assessment.host
        && service.port === assessment.port
        && Array.isArray(service.cve_candidates)
        && service.cve_candidates.some(
          (cve) => cve.id === String(assessment.finding_id).split(":")[0]
            && cve.match_status === "version_match",
        ),
      );
    });
  const recommendations = Array.isArray(result?.recommendations)
    ? result.recommendations
    : [];
  const displayResult = result && {
    ...result,
    services: services.map((service) => ({
      ...service,
      cve_candidates: versionMatchedCves(service),
    })),
    findings: findings.map((finding) => ({
      ...finding,
      cve_candidates: Array.isArray(finding.cve_candidates)
        ? finding.cve_candidates.filter((cve) => cve?.match_status === "version_match")
        : finding.cve_candidates,
    })),
    risk_assessments: riskAssessments,
  };
  const progress = scan?.progress;
  const progressLabel = typeof progress === "string"
    ? progress
    : progress && typeof progress === "object"
      ? progress.stage || progress.message || JSON.stringify(progress)
      : "Waiting for scanner status";

  return (
    <>
      <section className="page-intro"><div><span className="eyebrow">AUTHORIZED NETWORK ASSESSMENT</span><h2>AI-VulnScan</h2><p>Run an existing Nmap-based scan profile and review the scanner’s actual evidence, findings, and reports.</p></div><span className={`live-indicator ${health ? "service-online" : "service-offline"}`}>{health ? "API ONLINE" : "API OFFLINE"}</span></section>
      {error && <Notice error>{error}</Notice>}
      {!health && <Notice error>Vulnerability scanner API is unavailable. Other SentinelSuite modules remain independent.</Notice>}
      <Workflow />
      <section className="panel">
        <div className="panel-heading"><div><span className="eyebrow">NEW SCAN</span><h3>Target and profile</h3></div><Bug size={18} /></div>
        <form onSubmit={submit}>
          <div className="vuln-form-grid">
            <div className="vuln-field"><label htmlFor="vuln-target">Authorized IP, hostname, or CIDR</label><input id="vuln-target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="192.0.2.10 or example.org" autoComplete="off" required /></div>
            <div className="vuln-field"><label htmlFor="vuln-profile">Scan profile</label><select id="vuln-profile" value={profile} onChange={(event) => { setProfile(event.target.value); setConfirmComprehensive(false); setConfirmAggressive(false); setConfirmAllPorts(false); }} disabled={!profiles.length}>{profiles.map((item) => <option key={item.id || item} value={item.id || item}>{item.name || item.id || item}{item.description ? ` — ${item.description}` : ""}</option>)}</select></div>
          </div>
          <label className="vuln-authorize"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>I am authorized to scan this target and have approval for the selected profile.</span></label>
          {isCidr && <label className="vuln-authorize"><input type="checkbox" checked={confirmScope} onChange={(event) => setConfirmScope(event.target.checked)} /><span>I confirm this CIDR scope contains only hosts approved for scanning.</span></label>}
          {comprehensive && <label className="vuln-authorize"><input type="checkbox" checked={confirmComprehensive} onChange={(event) => setConfirmComprehensive(event.target.checked)} /><span>I understand the comprehensive profile performs the most extensive configured checks.</span></label>}
          {aggressive && <label className="vuln-authorize"><input type="checkbox" checked={confirmAggressive} onChange={(event) => setConfirmAggressive(event.target.checked)} /><span>I confirm this scan will probe all TCP ports with stronger service-version detection. It may take substantially longer and generate more network traffic; NSE scripts are not enabled.</span></label>}
          {allTcpUdp && <label className="vuln-authorize"><input type="checkbox" checked={confirmAllPorts} onChange={(event) => setConfirmAllPorts(event.target.checked)} /><span>I confirm this scan will probe every TCP and UDP port (1–65535) with stronger version detection. It may take a very long time; UDP may report open|filtered, which is not confirmed open. NSE scripts are not enabled.</span></label>}
          <button className="button primary" disabled={!canSubmit}><Search size={16} />{loading ? "Submitting..." : "Start authorized scan"}</button>
        </form>
        <p className="muted vuln-safety-note">Scans are submitted to the local scanner API. Never scan systems without explicit permission.</p>
      </section>
      {scan && <section className="panel result-panel">
        <div className="panel-heading"><div><span className="eyebrow">SCAN STATUS</span><h3>{scan.target || target}</h3></div><span className={`badge ${String(scan.status || "pending").toLowerCase()}`}>{scan.status || "queued"}</span></div>
        <p className="current-stage">{progressLabel}</p>
        {scan.error && <Notice error>{scan.error}</Notice>}
        {result && <>
          <div className="panel-heading vuln-result-heading"><h3>Risk and scan summary</h3><ShieldCheck size={18} /></div>
          <Summary value={result.summary || result.risk || result.risk_assessment} />
          <RiskAssessments items={riskAssessments} services={services} findings={findings} recommendations={recommendations} />
          <ServiceRows rows={services} />
          <section className="panel"><div className="panel-heading"><h3>Evidence-based findings</h3><span>{findings.length} findings</span></div><Findings items={findings} /></section>
          {recommendations.length > 0 && <section className="panel"><div className="panel-heading"><h3>Remediation recommendations</h3></div><div className="vuln-findings">{recommendations.map((item, index) => <article className="vuln-finding" key={`${item.problem || item.action || "recommendation"}-${index}`}><div className="vuln-finding-heading"><strong>{item.problem || item.title || "Recommended action"}</strong>{item.priority && <span className="badge warning">{item.priority}</span>}</div><p>{typeof item === "string" ? item : item.action || item.recommendation || item.description || JSON.stringify(item)}</p>{item.verification_steps && <p className="muted"><strong>Verification:</strong> {Array.isArray(item.verification_steps) ? item.verification_steps.join(" · ") : item.verification_steps}</p>}</article>)}</div></section>}
          <section className="panel vuln-details"><div className="panel-heading"><h3>Scanner result data</h3><div className="report-actions">{["md", "json", "html"].map((format) => <button className="button secondary" key={format} onClick={() => downloadReport(format)} disabled={reportLoading}><Download size={15} />{format.toUpperCase()}</button>)}</div></div><pre>{JSON.stringify(displayResult, null, 2)}</pre></section>
        </>}
      </section>}
      <section className="panel">
        <div className="panel-heading"><div><span className="eyebrow">MODULE HISTORY</span><h3>Previous scans</h3></div><button className="button secondary" onClick={refreshHistory}>Refresh</button></div>
        {historyError && <Notice error>{historyError}</Notice>}
        <div className="table-wrap"><table><thead><tr><th>Scan ID</th><th>Target</th><th>Profile</th><th>Status</th><th></th></tr></thead><tbody>
          {history.slice(0, 30).map((item, index) => {
            const id = scanIdentifier(item);
            return <tr key={id || index}><td className="mono">{id || "—"}</td><td>{item.target || "—"}</td><td>{item.profile || "—"}</td><td><span className={`badge ${String(item.status || "info").toLowerCase()}`}>{item.status || "—"}</span></td><td><button className="button secondary" onClick={() => id && openHistory(id)} disabled={!id}>View</button></td></tr>;
          })}
        </tbody></table>{!history.length && !historyError && <p className="muted table-empty">No scans have been recorded.</p>}</div>
      </section>
    </>
  );
}
