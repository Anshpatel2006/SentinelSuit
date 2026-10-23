import axios from "axios";

const api = axios.create({
  baseURL: "http://127.0.0.1:8000",
});

export async function getDashboardSummary() {
  const response = await api.get("/dashboard/summary");
  return response.data;
}

export async function getRecentAlerts() {
  const response = await api.get("/dashboard/recent-alerts");
  return response.data;
}

export async function getChartData() {
  const response = await api.get("/dashboard/charts");
  return response.data;
}

export default api;
