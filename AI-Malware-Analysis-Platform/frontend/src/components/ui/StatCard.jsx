export default function StatCard({ label, value, valueClass }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${valueClass ?? ""}`.trim()}>{value}</div>
    </div>
  );
}
