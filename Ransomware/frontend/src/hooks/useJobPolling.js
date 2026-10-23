import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { getJob } from "../api/client";
export function useJobPolling(job, setJob) {
  const navigate = useNavigate();

  useEffect(() => {
    if (!job || job.status === "completed" || job.status === "failed") return;

    const interval = setInterval(async () => {
      try {
        const updated = await getJob(job.job_id);
        setJob(updated);
        if (updated.status === "completed" && updated.result) {
          const sampleId = updated.result?.metadata?.sample_id;
          if (sampleId) navigate(`/reports/${sampleId}`);
        }
      } catch {
        /* ignore transient polling errors */
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [job, navigate, setJob]);
}
