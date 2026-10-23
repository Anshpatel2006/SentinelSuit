export function riskClass(level) {
  if (!level) return "badge";
  return `badge badge-${level.toLowerCase()}`;
}

export default function RiskBadge({ level, score }) {
  return (
    <span className={riskClass(level)}>
      {level?.toUpperCase() || "—"}
      {score != null ? ` (${score})` : ""}
    </span>
  );
}
