import { Bell, Search, CircleUser } from "lucide-react";

function Navbar() {
  return (
    <header className="bg-white border-b border-slate-200 px-8 py-5 flex justify-between items-center">

      <div>
        <p className="text-xs uppercase tracking-wider text-slate-400">
          SentinelIDS
        </p>

        <h2 className="text-2xl font-bold text-slate-800 mt-1">
          Security Dashboard
        </h2>
      </div>

      <div className="flex items-center gap-5">

        <div className="flex items-center gap-3 bg-slate-100 px-4 py-2 rounded-xl w-72">
          <Search size={18} className="text-slate-400" />

          <input
            placeholder="Search alerts, IP..."
            className="bg-transparent outline-none text-sm w-full"
          />
        </div>

        <button className="relative p-2 rounded-xl hover:bg-slate-100 transition">
          <Bell size={21} className="text-slate-600" />

          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500"></span>
        </button>

        <div className="flex items-center gap-3 pl-2 border-l border-slate-200">
          <CircleUser size={34} className="text-blue-600" />

          <div>
            <p className="text-sm font-semibold text-slate-700">
              Vidisha Patel
            </p>

            <p className="text-xs text-slate-500">
              Security Analyst
            </p>
          </div>
        </div>

      </div>

    </header>
  );
}

export default Navbar;
