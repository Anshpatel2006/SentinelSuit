import { NavLink } from "react-router-dom";

const links = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/upload", label: "Upload Sample" },
  { to: "/jobs", label: "Active Jobs" },
  { to: "/phishing", label: "Phishing Scanner" },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">🛡</div>
        <div>
          <div className="brand-title">Malware Platform</div>
          <div className="brand-sub">AI Analysis Suite</div>
        </div>
      </div>
      <nav>
        {links.map(({ to, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
          >
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
