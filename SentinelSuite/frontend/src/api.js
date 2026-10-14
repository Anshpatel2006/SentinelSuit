const services = {
  ransomware: import.meta.env.VITE_RANSOMWARE_API_URL || "http://127.0.0.1:8080/api/v1",
  phishing: import.meta.env.VITE_PHISHING_API_URL || "http://127.0.0.1:8000/api",
  ids: import.meta.env.VITE_IDS_API_URL || "http://127.0.0.1:8002",
};

async function request(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
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
  ransomwareReportPdf: (sampleId) => fetch(`${services.ransomware}/reports/${sampleId}/pdf`),
  phishingHealth: () => request(`${services.phishing}/health`),
  phishingModel: () => request(`${services.phishing}/model-info`),
  phishingScan: (url) => request(`${services.phishing}/scan`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }),
  }),
  phishingReport: (result) => request(`${services.phishing}/report`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(result),
  }),
  idsHealth: () => request(`${services.ids}/health`),
  idsSummary: () => request(`${services.ids}/dashboard/summary`),
  idsAlerts: () => request(`${services.ids}/dashboard/recent-alerts`),
  idsFullReport: () => request(`${services.ids}/dashboard/full-report`),
  idsCaptureStatus: () => request(`${services.ids}/dashboard/capture-status`),
  idsScans: () => request(`${services.ids}/scans`),
  idsReports: () => request(`${services.ids}/reports`),
};
