const services = {
  ransomware: import.meta.env.VITE_RANSOMWARE_API_URL || "http://127.0.0.1:8080/api/v1",
  phishing: import.meta.env.VITE_PHISHING_API_URL || "http://127.0.0.1:8001/api",
  ids: import.meta.env.VITE_IDS_API_URL || "http://127.0.0.1:8002",
  vulnscan: import.meta.env.VITE_VULNSCAN_API_URL || "http://127.0.0.1:8765",
};

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error(`Request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function request(url, options, timeoutMs) {
  const response = await fetchWithTimeout(url, options, timeoutMs);
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`Service returned an invalid JSON response (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    throw new Error(payload?.detail || payload?.message || `Request failed (HTTP ${response.status}).`);
  }
  if (payload === null) throw new Error(`Service returned an empty response (HTTP ${response.status}).`);
  return payload;
}

async function requestFile(url, options, timeoutMs = 60000) {
  const response = await fetchWithTimeout(url, options, timeoutMs);
  if (!response.ok) {
    const text = await response.text();
    let detail;
    try {
      detail = JSON.parse(text)?.detail;
    } catch {
      detail = text.trim();
    }
    throw new Error(detail || `Request failed (HTTP ${response.status}).`);
  }
  return response;
}

export const api = {
  services,
  ransomwareHealth: () => request(`${services.ransomware}/health`),
  ransomwareReports: () => request(`${services.ransomware}/reports`),
  ransomwareJobs: () => request(`${services.ransomware}/jobs`),
  ransomwareUpload: (file, continueToCape = false) => {
    const form = new FormData();
    form.append("file", file);
    form.append("continue_to_cape", String(continueToCape));
    return request(`${services.ransomware}/analyze`, { method: "POST", body: form });
  },
  ransomwareJob: (id) => request(`${services.ransomware}/jobs/${id}`),
  ransomwareReport: (sampleId) => request(`${services.ransomware}/reports/${sampleId}`),
  ransomwareReportPdf: (sampleId) => requestFile(`${services.ransomware}/reports/${encodeURIComponent(sampleId)}/pdf`),
  phishingHealth: () => request(`${services.phishing}/health`),
  phishingModel: () => request(`${services.phishing}/model-info`),
  phishingScan: (url) => request(`${services.phishing}/scan`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }),
  }, 60000),
  phishingReport: (result) => requestFile(`${services.phishing}/report`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(result),
  }),
  idsHealth: () => request(`${services.ids}/health`),
  idsSummary: () => request(`${services.ids}/dashboard/summary`),
  idsAlerts: () => request(`${services.ids}/dashboard/recent-alerts`),
  idsFullReport: () => request(`${services.ids}/dashboard/full-report`),
  idsCaptureStatus: () => request(`${services.ids}/dashboard/capture-status`),
  vulnscanHealth: () => request(`${services.vulnscan}/health`),
  vulnscanProfiles: () => request(`${services.vulnscan}/profiles`),
  vulnscanHistory: () => request(`${services.vulnscan}/scans`),
  vulnscanSubmit: (scan) => request(`${services.vulnscan}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(scan),
  }, 30000),
  vulnscanGet: (scanId) => request(`${services.vulnscan}/scans/${encodeURIComponent(scanId)}`, {}, 30000),
  vulnscanReport: (scanId, format = "html") => requestFile(
    `${services.vulnscan}/scans/${encodeURIComponent(scanId)}/report?format=${encodeURIComponent(format)}`,
    {},
  ),
};
