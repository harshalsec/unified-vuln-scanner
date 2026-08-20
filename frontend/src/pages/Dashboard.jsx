import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getJobs } from "../services/api";
import { Shield, AlertTriangle, CheckCircle, Clock } from "lucide-react";

export default function Dashboard() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    loadJobs();
    const interval = setInterval(loadJobs, 5000); // auto refresh every 5s
    return () => clearInterval(interval);
  }, []);

  const loadJobs = async () => {
    try {
      const data = await getJobs();
      setJobs(data);
    } catch (error) {
      console.error("Failed to load jobs:", error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status) => {
    const styles = {
      completed: "bg-emerald-500/10 text-emerald-400",
      running: "bg-blue-500/10 text-blue-400",
      failed: "bg-red-500/10 text-red-400",
      pending: "bg-yellow-500/10 text-yellow-400",
    };
    return styles[status] || "bg-gray-500/10 text-gray-400";
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-gray-400 mt-1">Overview of your vulnerability scans</p>
        </div>
        <Link
          to="/new-scan"
          className="bg-emerald-600 hover:bg-emerald-500 px-5 py-2.5 rounded-lg font-medium transition"
        >
          New Scan
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-emerald-400" />
            <span className="text-gray-400 text-sm">Total Scans</span>
          </div>
          <p className="text-2xl font-bold mt-2">{jobs.length}</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <CheckCircle className="w-5 h-5 text-emerald-400" />
            <span className="text-gray-400 text-sm">Completed</span>
          </div>
          <p className="text-2xl font-bold mt-2">
            {jobs.filter((j) => j.status === "completed").length}
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <Clock className="w-5 h-5 text-blue-400" />
            <span className="text-gray-400 text-sm">Running</span>
          </div>
          <p className="text-2xl font-bold mt-2">
            {jobs.filter((j) => j.status === "running").length}
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <span className="text-gray-400 text-sm">Failed</span>
          </div>
          <p className="text-2xl font-bold mt-2">
            {jobs.filter((j) => j.status === "failed").length}
          </p>
        </div>
      </div>

      {/* Jobs Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold">Recent Scans</h2>
        </div>

        {loading ? (
          <div className="p-8 text-center text-gray-400">Loading...</div>
        ) : jobs.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
              <Shield className="w-7 h-7 text-gray-500" />
            </div>
            <h3 className="text-lg font-medium text-gray-300 mb-1">No scans yet</h3>
            <p className="text-gray-500 text-sm mb-5">
              Start your first vulnerability scan to see results here.
            </p>
            <Link
              to="/new-scan"
              className="inline-flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg text-sm font-medium transition"
            >
              Create New Scan
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-950 text-gray-400">
                <tr>
                  <th className="text-left px-6 py-3">Engine</th>
                  <th className="text-left px-6 py-3">Target</th>
                  <th className="text-left px-6 py-3">Status</th>
                  <th className="text-left px-6 py-3">Findings</th>
                  <th className="text-left px-6 py-3">Created</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr
                    key={job.id}
                    onClick={() => navigate(`/jobs/${job.id}`)}
                    className="border-t border-gray-800 hover:bg-gray-800/50 cursor-pointer transition"
                  >
                    <td className="px-6 py-4 font-medium capitalize">
                      {job.engine.replace("_", " ")}
                    </td>
                    <td className="px-6 py-4 text-gray-300 max-w-xs truncate">
                      {job.target}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize ${getStatusBadge(job.status)}`}>
                        {job.status}
                      </span>
                    </td>
                    <td className="px-6 py-4">{job.findings?.length || 0}</td>
                    <td className="px-6 py-4 text-gray-400">
                      {new Date(job.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}