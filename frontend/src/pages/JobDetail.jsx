import { useEffect, useState, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import { getJob } from "../services/api";
import { ArrowLeft, AlertTriangle, Activity } from "lucide-react";

export default function JobDetail() {
  const { id } = useParams();
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(true);
  const [progress, setProgress] = useState(null);
  const [logs, setLogs] = useState([]);
  const wsRef = useRef(null);

  useEffect(() => {
    loadJob();
    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [id]);

  const loadJob = async () => {
    try {
      const data = await getJob(id);
      setJob(data);
    } catch (error) {
      console.error("Failed to load job:", error);
    } finally {
      setLoading(false);
    }
  };

  const connectWebSocket = () => {
    const ws = new WebSocket(`ws://localhost:8000/ws/jobs/${id}`);
    wsRef.current = ws;

    ws.onopen = () => {
      addLog("Connected to live updates");
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "progress") {
        setProgress({
          percentage: data.percentage,
          message: data.message,
        });
        addLog(`[${data.percentage}%] ${data.message}`);
      }

      if (data.type === "status") {
        addLog(data.message);
        // Refresh job data when status changes
        loadJob();
      }

      if (data.type === "completed" || data.type === "failed") {
        addLog(data.message || "Scan finished");
        setProgress(null);
        loadJob(); // final refresh
      }

      if (data.type === "connected") {
        addLog("WebSocket connected");
      }
    };

    ws.onclose = () => {
      addLog("Disconnected from live updates");
    };

    ws.onerror = () => {
      addLog("WebSocket connection error");
    };
  };

  const addLog = (message) => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [`[${time}] ${message}`, ...prev].slice(0, 50));
  };

  if (loading) {
    return <div className="text-center text-gray-400 py-20">Loading...</div>;
  }

  if (!job) {
    return <div className="text-center text-red-400 py-20">Job not found</div>;
  }

  return (
    <div>
      <Link
        to="/"
        className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-6 transition"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>

      {/* Job Header */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold mb-1 capitalize">
              {job.engine.replace("_", " ")}
            </h1>
            <p className="text-gray-400 break-all">{job.target}</p>
          </div>
          <span
            className={`px-3 py-1 rounded-full text-sm font-medium capitalize
              ${job.status === "completed" ? "bg-emerald-500/10 text-emerald-400" : ""}
              ${job.status === "running" ? "bg-blue-500/10 text-blue-400" : ""}
              ${job.status === "failed" ? "bg-red-500/10 text-red-400" : ""}
              ${job.status === "pending" ? "bg-yellow-500/10 text-yellow-400" : ""}
            `}
          >
            {job.status}
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 text-sm">
          <div>
            <p className="text-gray-500">Job ID</p>
            <p className="font-mono text-xs mt-1 break-all">{job.id}</p>
          </div>
          <div>
            <p className="text-gray-500">Findings</p>
            <p className="mt-1 font-medium">{job.findings?.length || 0}</p>
          </div>
          <div>
            <p className="text-gray-500">Created</p>
            <p className="mt-1">{new Date(job.created_at).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-gray-500">Timeout</p>
            <p className="mt-1">{job.timeout_seconds}s</p>
          </div>
        </div>

        {job.error_message && (
          <div className="mt-4 text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded-lg px-4 py-3">
            {job.error_message}
          </div>
        )}
      </div>

      {/* Live Progress */}
      {progress && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-4 h-4 text-blue-400 animate-pulse" />
            <h2 className="font-semibold">Live Progress</h2>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-3 mb-2">
            <div
              className="bg-emerald-500 h-3 rounded-full transition-all duration-300"
              style={{ width: `${progress.percentage}%` }}
            ></div>
          </div>
          <p className="text-sm text-gray-400">
            {progress.percentage}% — {progress.message}
          </p>
        </div>
      )}

      {/* Live Logs */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden mb-6">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold">Live Logs</h2>
        </div>
        <div className="p-4 max-h-60 overflow-y-auto font-mono text-xs text-gray-300 space-y-1">
          {logs.length === 0 ? (
            <p className="text-gray-500">Waiting for updates...</p>
          ) : (
            logs.map((log, i) => <div key={i}>{log}</div>)
          )}
        </div>
      </div>

      {/* Findings */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-yellow-400" />
          <h2 className="font-semibold">Findings ({job.findings?.length || 0})</h2>
        </div>

        {!job.findings || job.findings.length === 0 ? (
          <div className="p-8 text-center text-gray-400">
            No findings detected for this scan.
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {job.findings.map((finding, index) => (
              <div key={index} className="p-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h3 className="font-medium">{finding.title}</h3>
                    <p className="text-sm text-gray-400 mt-1 whitespace-pre-line">
                      {finding.description}
                    </p>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-medium uppercase
                      ${finding.severity === "critical" ? "bg-red-500/20 text-red-400" : ""}
                      ${finding.severity === "high" ? "bg-orange-500/20 text-orange-400" : ""}
                      ${finding.severity === "medium" ? "bg-yellow-500/20 text-yellow-400" : ""}
                      ${finding.severity === "low" ? "bg-blue-500/20 text-blue-400" : ""}
                    `}
                  >
                    {finding.severity}
                  </span>
                </div>

                {finding.remediation && (
                  <div className="mt-3 text-sm">
                    <p className="text-gray-500 mb-1">Remediation</p>
                    <p className="text-gray-300">{finding.remediation}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}