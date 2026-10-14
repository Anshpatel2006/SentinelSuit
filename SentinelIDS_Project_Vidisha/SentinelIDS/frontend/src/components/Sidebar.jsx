import {
  Shield,
  LayoutDashboard,
  TriangleAlert,
  BarChart3,
  Radar,
  Brain,
  Activity,
  Settings,
  ChevronRight
} from "lucide-react";

const menuItems = [
  { icon: LayoutDashboard, title: "Dashboard", active: true },
  { icon: TriangleAlert, title: "Alerts" },
  { icon: Activity, title: "Live Monitor" },
  { icon: BarChart3, title: "Analytics" },
  { icon: Radar, title: "Scanner" },
  { icon: Brain, title: "AI Reports" },
  { icon: Settings, title: "Settings" },
];

function Sidebar() {
  return (
    <aside className="w-72 h-screen bg-white border-r border-slate-200 flex flex-col">

      <div className="px-6 py-7 border-b border-slate-200">
        <div className="flex items-center gap-3">
          <div className="bg-blue-600 p-3 rounded-xl">
            <Shield size={22} className="text-white" />
          </div>

          <div>
            <h1 className="font-bold text-xl text-slate-800">
              SentinelIDS
            </h1>

            <p className="text-xs text-slate-500">
              Hybrid AI Intrusion Detection
            </p>
          </div>
        </div>
      </div>

      <div className="flex-1 px-4 py-6 space-y-2">

        {menuItems.map((item) => {
          const Icon = item.icon;

          return (
            <button
              key={item.title}
              className={`w-full flex items-center justify-between px-4 py-3 rounded-xl transition
                ${
                  item.active
                    ? "bg-blue-600 text-white"
                    : "text-slate-600 hover:bg-slate-100"
                }`}
            >
              <div className="flex items-center gap-3">
                <Icon size={20} />
                <span className="font-medium text-sm">{item.title}</span>
              </div>

              {item.active && <ChevronRight size={18} />}
            </button>
          );
        })}

      </div>

      <div className="p-4 border-t border-slate-200">

        <div className="rounded-2xl bg-slate-50 border border-slate-200 p-4">
          <p className="text-xs text-slate-500">SYSTEM STATUS</p>

          <div className="flex items-center gap-2 mt-3">
            <div className="w-2 h-2 rounded-full bg-green-500"></div>

            <span className="text-sm text-slate-700 font-medium">
              Backend Connected
            </span>
          </div>

          <div className="mt-4">
            <p className="text-xs text-slate-500 mb-2">
              Threat Detection Engine
            </p>

            <div className="w-full bg-slate-200 rounded-full h-2">
              <div className="bg-blue-600 h-2 rounded-full w-full"></div>
            </div>

            <p className="text-xs text-blue-600 mt-2 font-medium">
              Ready
            </p>
          </div>

        </div>

      </div>

    </aside>
  );
}

export default Sidebar;
