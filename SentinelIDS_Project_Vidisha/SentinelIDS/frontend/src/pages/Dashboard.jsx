import { useEffect, useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Radar,
  Brain,
  Activity,
  Clock,
} from "lucide-react";

import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts";

import {
  getDashboardSummary,
  getRecentAlerts,
  getChartData,
} from "../services/api";

function Dashboard() {
  // ================= Summary =================

  const [summary, setSummary] = useState({
    total_alerts: 0,
    high_alerts: 0,
    critical_alerts: 0,
    medium_alerts: 0,
    low_alerts: 0,
    scan_count: 0,
    report_count: 0,
  });

  // ================= Live Dashboard Data =================

  const [alerts, setAlerts] = useState([]);
  const [trafficData, setTrafficData] = useState([]);
  const [attackData, setAttackData] = useState([]);
  const [severityData, setSeverityData] = useState([]);

  const [loading, setLoading] = useState(true);

  useEffect(() => {
  loadDashboard();

  const interval = setInterval(() => {
    loadDashboard();
  }, 5000);

  return () => clearInterval(interval);
  }, []);

  async function loadDashboard() {
    try {
      const summaryData = await getDashboardSummary();
      setSummary(summaryData);

      const alertData = await getRecentAlerts();
      setAlerts(alertData);

      const chartData = await getChartData();

      setTrafficData(chartData.traffic || []);
      setAttackData(chartData.attacks || []);
      setSeverityData(chartData.severity || []);
    } catch (error) {
      console.log("Dashboard API Error:", error);
    } finally {
      setLoading(false);
    }
  }

  // ================= Summary Cards =================

  const cards = [
    {
      title: "Total Alerts",
      value: summary.total_alerts,
      icon: ShieldAlert,
      color: "text-blue-600",
      bg: "bg-blue-50",
    },
    {
      title: "High Risk Alerts",
      value: summary.high_alerts + summary.critical_alerts,
      icon: ShieldCheck,
      color: "text-red-600",
      bg: "bg-red-50",
    },
    {
      title: "Scanned Hosts",
      value: summary.scan_count,
      icon: Radar,
      color: "text-emerald-600",
      bg: "bg-emerald-50",
    },
    {
      title: "AI Reports",
      value: summary.report_count,
      icon: Brain,
      color: "text-violet-600",
      bg: "bg-violet-50",
    },
  ];

  const pieColors = [
    "#2563EB",
    "#EF4444",
    "#10B981",
    "#7C3AED",
    "#F59E0B",
    "#0EA5E9",
  ];

  return (
    <div className="space-y-8">
          {/* ================= Header ================= */}

      <div>
        <p className="text-sm text-slate-500">SentinelIDS / Dashboard</p>

        <h1 className="text-3xl font-bold text-slate-800 mt-1">
          Security Overview
        </h1>

        <p className="text-slate-500 mt-2">
          AI-powered Hybrid Intrusion Detection Dashboard
        </p>
      </div>

      {/* ================= Summary Cards ================= */}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">
        {cards.map((card) => {
          const Icon = card.icon;

          return (
            <div
              key={card.title}
              className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition"
            >
              <div className="flex items-center justify-between">
                <div className={`${card.bg} p-3 rounded-xl`}>
                  <Icon className={card.color} size={22} />
                </div>

                <Activity className="text-slate-300" size={18} />
              </div>

              <p className="text-sm text-slate-500 mt-6">
                {card.title}
              </p>

              <h2 className={`text-3xl font-bold mt-2 ${card.color}`}>
                {loading ? "..." : card.value}
              </h2>
            </div>
          );
        })}
      </div>

      {/* ================= Threat Analytics + Status ================= */}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">

        {/* Area Chart */}

        <div className="xl:col-span-2 bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">

          <div className="flex items-center justify-between mb-5">
            <h2 className="text-lg font-semibold text-slate-800">
              Network Threat Activity
            </h2>

            <span className="text-xs bg-blue-50 text-blue-600 px-3 py-1 rounded-full">
              Live Alerts
            </span>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData}>
                <CartesianGrid stroke="#E2E8F0" strokeDasharray="4 4" />

                <XAxis
                  dataKey="time"
                  tick={{ fill: "#64748B", fontSize: 12 }}
                />

                <YAxis
                  tick={{ fill: "#64748B", fontSize: 12 }}
                />

                <Tooltip />

                <Area
                  type="monotone"
                  dataKey="alerts"
                  stroke="#2563EB"
                  fill="#DBEAFE"
                  strokeWidth={3}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <p className="text-xs text-slate-400 mt-4">
            Alerts captured by SentinelIDS grouped by time.
          </p>

        </div>

        {/* System Status */}

        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">

          <h2 className="text-lg font-semibold text-slate-800 mb-6">
            System Status
          </h2>

          <div className="space-y-5">

            <StatusRow title="Backend API" text="Online" color="green" />

            <StatusRow title="ML Detector" text="Active" color="green" />

            <StatusRow title="Signature IDS" text="Running" color="green" />

            <StatusRow title="Network Scanner" text="Ready" color="blue" />

            <StatusRow title="AI Analysis" text="Connected" color="violet" />

            <StatusRow
              title="Captured Alerts"
              text={loading ? "Loading..." : String(summary.total_alerts)}
              color="blue"
            />

          </div>

        </div>

      </div>
      
            {/* ================= Attack Distribution + Severity Chart ================= */}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">

        {/* -------- Attack Type Distribution -------- */}

        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">

          <div className="flex items-center justify-between mb-5">
            <h2 className="text-lg font-semibold text-slate-800">
              Attack Type Distribution
            </h2>

            <span className="text-xs bg-slate-100 text-slate-600 px-3 py-1 rounded-full">
              Live
            </span>
          </div>

          <div className="h-64">

            <ResponsiveContainer width="100%" height="100%">
              <PieChart>

                <Pie
                  data={attackData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={2}
                >
                  {attackData.map((entry, index) => (
                    <Cell
                      key={entry.name}
                      fill={pieColors[index % pieColors.length]}
                    />
                  ))}
                </Pie>

                <Tooltip />

              </PieChart>
            </ResponsiveContainer>

          </div>

          {/* Legend */}

          <div className="space-y-3 mt-5">

            {attackData.length === 0 ? (
              <p className="text-sm text-slate-400">
                No attacks detected yet.
              </p>
            ) : (
              attackData.map((item, index) => (
                <div
                  key={item.name}
                  className="flex items-center justify-between"
                >

                  <div className="flex items-center gap-3">

                    <div
                      className="w-3 h-3 rounded-full"
                      style={{
                        backgroundColor:
                          pieColors[index % pieColors.length],
                      }}
                    />

                    <span className="text-sm text-slate-600">
                      {item.name}
                    </span>

                  </div>

                  <span className="text-sm font-semibold text-slate-800">
                    {item.value}
                  </span>

                </div>
              ))
            )}

          </div>

        </div>

        {/* -------- Severity Distribution -------- */}

        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">

          <div className="flex items-center justify-between mb-5">
            <h2 className="text-lg font-semibold text-slate-800">
              Alert Severity Distribution
            </h2>

            <span className="text-xs bg-slate-100 text-slate-600 px-3 py-1 rounded-full">
              Live
            </span>
          </div>

          <div className="h-72">

            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>

                <CartesianGrid strokeDasharray="4 4" stroke="#E2E8F0" />

                <XAxis
                  dataKey="level"
                  tick={{ fill: "#64748B", fontSize: 12 }}
                />

                <YAxis
                  tick={{ fill: "#64748B", fontSize: 12 }}
                />

                <Tooltip />

                <Bar
                  dataKey="count"
                  radius={[8, 8, 0, 0]}
                >
                  {severityData.map((entry) => {
                    let color = "#CBD5E1";

                    if (entry.level === "LOW") color = "#64748B";
                    if (entry.level === "MEDIUM") color = "#F59E0B";
                    if (entry.level === "HIGH") color = "#EA580C";
                    if (entry.level === "CRITICAL") color = "#DC2626";

                    return (
                      <Cell key={entry.level} fill={color} />
                    );
                  })}
                </Bar>

              </BarChart>
            </ResponsiveContainer>

          </div>

          {/* Severity Summary */}

          <div className="grid grid-cols-2 gap-3 mt-5">

            {severityData.map((item) => (
              <div
                key={item.level}
                className="rounded-xl bg-slate-50 border border-slate-200 p-3"
              >
                <p className="text-xs text-slate-500">
                  {item.level}
                </p>

                <h3 className="text-xl font-bold text-slate-800 mt-1">
                  {item.count}
                </h3>
              </div>
            ))}

          </div>

        </div>

      </div>
            {/* ================= Recent Security Alerts ================= */}

      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">

        <div className="flex items-center justify-between px-6 py-5 border-b border-slate-200">
          <div>
            <h2 className="text-lg font-semibold text-slate-800">
              Recent Security Alerts
            </h2>

            <p className="text-sm text-slate-500 mt-1">
              Latest high-risk incidents detected by SentinelIDS
            </p>
          </div>

          <span className="text-xs bg-blue-50 text-blue-600 px-3 py-1 rounded-full">
            {alerts.length} Alerts
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">

            <thead className="bg-slate-50 text-slate-500">
              <tr>
                <th className="text-left px-6 py-4">Attack Type</th>
                <th className="text-left px-6 py-4">Severity</th>
                <th className="text-left px-6 py-4">Source IP</th>
                <th className="text-left px-6 py-4">Target IP</th>
                <th className="text-left px-6 py-4">Protocol</th>
                <th className="text-left px-6 py-4">Risk Score</th>
                <th className="text-left px-6 py-4">Detected</th>
              </tr>
            </thead>

            <tbody>

              {alerts.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-6 py-10 text-center text-slate-400"
                  >
                    No security alerts captured yet.
                  </td>
                </tr>
              ) : (
                alerts.map((alert, index) => (
                  <tr
                    key={index}
                    className="border-t border-slate-100 hover:bg-slate-50 transition"
                  >
                    <td className="px-6 py-4 font-semibold text-slate-700">
                      {alert.attack}
                    </td>

                    <td className="px-6 py-4">
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-medium ${
                          alert.severity === "CRITICAL"
                            ? "bg-red-100 text-red-700"
                            : alert.severity === "HIGH"
                            ? "bg-orange-100 text-orange-700"
                            : alert.severity === "MEDIUM"
                            ? "bg-yellow-100 text-yellow-700"
                            : "bg-slate-100 text-slate-700"
                        }`}
                      >
                        {alert.severity}
                      </span>
                    </td>

                    <td className="px-6 py-4 text-slate-600">
                      {alert.source_ip}
                    </td>

                    <td className="px-6 py-4 text-slate-600">
                      {alert.destination_ip}
                    </td>

                    <td className="px-6 py-4 text-slate-600">
                      {alert.protocol}
                    </td>

                    <td className="px-6 py-4">
                      <span
                        className={`font-semibold ${
                          alert.risk_score >= 90
                            ? "text-red-700"
                            : alert.risk_score >= 70
                            ? "text-orange-600"
                            : "text-slate-600"
                        }`}
                      >
                        {alert.risk_score}
                      </span>
                    </td>

                    <td className="px-6 py-4 text-slate-500">
                      <div className="flex items-center gap-2">
                        <Clock size={14} />

                        {alert.timestamp
                          ? new Date(alert.timestamp * 1000).toLocaleTimeString(
                              "en-IN",
                              {
                                hour: "2-digit",
                                minute: "2-digit",
                                second: "2-digit",
                              }
                            )
                          : "--"}
                      </div>
                    </td>
                  </tr>
                ))
              )}

            </tbody>

          </table>
        </div>

      </div>

    </div>
  );
}

// ================= Reusable Status Row =================

function StatusRow({ title, text, color }) {
  const colors = {
    green: "text-green-600",
    blue: "text-blue-600",
    violet: "text-violet-600",
  };

  return (
    <div className="flex justify-between items-center py-2">
      <span className="text-slate-500">{title}</span>

      <span className={`font-medium ${colors[color]}`}>
        {text}
      </span>
    </div>
  );
}

export default Dashboard;
