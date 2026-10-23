const API_BASE = "/api/v1";

async function request(path, init) {
  const res = await fetch(`${API_BASE}${path}`, init);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Request failed: ${path}`);
  }
  return res.json();
}

export function getHealth() {
  return request("/health");
}

export function uploadSample(file, continueToCape = false) {
  const form = new FormData();
  form.append("file", file);
  form.append("continue_to_cape", String(continueToCape));
  return request("/analyze", { method: "POST", body: form });
}

export function getJob(jobId) {
  return request(`/jobs/${jobId}`);
}

export function listJobs() {
  return request("/jobs");
}

export function listReports() {
  return request("/reports");
}

export function getReport(sampleId) {
  return request(`/reports/${sampleId}`);
}

export async function downloadReportPdf(sampleId) {
  const response = await fetch(`/api/v1/reports/${sampleId}/pdf`);
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to download PDF report");
  }
  return response.blob();
}
