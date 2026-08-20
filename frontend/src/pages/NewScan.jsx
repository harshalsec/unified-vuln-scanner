import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createJob, runJob } from "../services/api";

export default function NewScan() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    engine: "reflected_xss",
    target: "",
    timeout_seconds: 30,
    low_privilege_token: "",
    high_privilege_token: "",
  });

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const jobData = {
        engine: form.engine,
        target: form.target,
        additional_targets: [],
        options: {},
        timeout_seconds: Number(form.timeout_seconds),
      };

      // Add identity_pair only for BOLA
      if (form.engine === "bola") {
        if (!form.low_privilege_token || !form.high_privilege_token) {
          setError("Both Low and High privilege tokens are required for BOLA scans.");
          setLoading(false);
          return;
        }

        jobData.identity_pair = {
          low_privilege_token: form.low_privilege_token,
          high_privilege_token: form.high_privilege_token,
          low_privilege_user_id: "low_user",
          high_privilege_user_id: "high_user",
        };
      }

      const job = await createJob(jobData);
      await runJob(job.id);
      navigate("/");
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || "Failed to create scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-3xl font-bold mb-2">New Scan</h1>
      <p className="text-gray-400 mb-8">Configure and launch a vulnerability scan</p>

      <form onSubmit={handleSubmit} className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-6">
        
        {/* Engine Select */}
        <div>
          <label className="block text-sm font-medium mb-2">Scan Engine</label>
          <select
            name="engine"
            value={form.engine}
            onChange={handleChange}
            className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 focus:outline-none focus:border-emerald-500"
          >
            <option value="reflected_xss">Reflected XSS</option>
            <option value="subdomain_takeover">Subdomain Takeover</option>
            <option value="bola">BOLA / IDOR</option>
          </select>
        </div>

        {/* Target */}
        <div>
          <label className="block text-sm font-medium mb-2">Target URL / Domain</label>
          <input
            type="text"
            name="target"
            value={form.target}
            onChange={handleChange}
            placeholder="https://example.com"
            required
            className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 focus:outline-none focus:border-emerald-500"
          />
        </div>

        {/* BOLA specific fields */}
        {form.engine === "bola" && (
          <>
            <div className="bg-gray-950 border border-gray-700 rounded-lg p-4 space-y-4">
              <p className="text-sm text-yellow-400 font-medium">
                BOLA requires two authentication tokens
              </p>

              <div>
                <label className="block text-sm font-medium mb-2">Low Privilege Token</label>
                <input
                  type="text"
                  name="low_privilege_token"
                  value={form.low_privilege_token}
                  onChange={handleChange}
                  placeholder="Token of low privilege user"
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">High Privilege Token</label>
                <input
                  type="text"
                  name="high_privilege_token"
                  value={form.high_privilege_token}
                  onChange={handleChange}
                  placeholder="Token of high privilege user"
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
          </>
        )}

        {/* Timeout */}
        <div>
          <label className="block text-sm font-medium mb-2">Timeout (seconds)</label>
          <input
            type="number"
            name="timeout_seconds"
            value={form.timeout_seconds}
            onChange={handleChange}
            min="30"
            max="300"
            className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 focus:outline-none focus:border-emerald-500"
          />
        </div>

        {error && (
          <div className="text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded-lg px-4 py-3">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:cursor-not-allowed py-3 rounded-lg font-medium transition"
        >
          {loading ? "Starting Scan..." : "Start Scan"}
        </button>
      </form>
    </div>
  );
}