import { Route, Routes } from "react-router-dom";
import AppShell from "./components/layout/AppShell";
import Dashboard from "./pages/Dashboard";
import Jobs from "./pages/Jobs";
import ReportDetail from "./pages/ReportDetail";
import Upload from "./pages/Upload";
import Phishing from "./pages/Phishing";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/jobs" element={<Jobs />} />
        <Route path="/reports/:sampleId" element={<ReportDetail />} />
        <Route path="/phishing" element={<Phishing />} />
      </Route>
    </Routes>
  );
}
