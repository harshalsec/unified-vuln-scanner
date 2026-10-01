import { useState, useRef, useEffect } from "react";
import axios from "axios";
import { Send, Bot, User, Shield, RotateCcw, Play, SkipForward } from "lucide-react";

const API = "http://localhost:8000/api/v1/chat";

export default function ChatScan() {
  const [messages, setMessages] = useState([
    {
      role: "bot",
      text: "Hi! I'm your AI Vulnerability Scanner.\n\nSend me a target URL (e.g. https://example.com) and I will automatically check multiple vulnerabilities.\n\nYou can skip any engine that needs extra data.",
    },
  ]);
  const [input, setInput] = useState("");
  const [sessionId, setSessionId] = useState(null);
  const [status, setStatus] = useState("idle");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const addMessage = (role, text, type = "text", severity = null) => {
    setMessages((prev) => [...prev, { role, text, type, severity }]);
};

  const resetChat = () => {
    setMessages([
      {
        role: "bot",
        text: "New session started. Send me a target URL to begin.",
      },
    ]);
    setSessionId(null);
    setStatus("idle");
    setInput("");
  };

  const handleSend = async (overrideText = null) => {
    const text = (overrideText || input).trim();
    if (!text || loading) return;

    addMessage("user", text);
    if (!overrideText) setInput("");
    setLoading(true);

    try {
      // Start new session
      if (!sessionId) {
        const res = await axios.post(`${API}/start`, { target: text });
        setSessionId(res.data.session_id);
        setStatus(res.data.status);
        addMessage("bot", res.data.message);

        if (res.data.questions?.length > 0) {
          res.data.questions.forEach((q) => addMessage("bot", q.question));
        } else {
          addMessage("bot", "All set! Click **Run Scan** or type 'run'.");
        }
      }
      // Run scan
      else if (["run", "start scan", "start"].includes(text.toLowerCase())) {
        setStatus("running");
        addMessage("bot", "🚀 Starting multi-engine scan... Please wait.");

        const res = await axios.post(`${API}/run`, { session_id: sessionId });
        setStatus("completed");
        addMessage("bot", res.data.message);

        if (res.data.results) {
          // Summary card
          let summary = "📊 Scan Summary\n";
          res.data.results.forEach((r) => {
            const icon = r.findings_count > 0 ? "🔴" : "✅";
            summary += `\n${icon} ${r.engine}: ${r.findings_count} finding(s) • ${r.duration_seconds}s`;
          });

          if (res.data.skipped_engines?.length) {
            summary += `\n\n⏭ Skipped: ${res.data.skipped_engines.join(", ")}`;
          }
          summary += `\n\n🎯 Total Findings: ${res.data.total_findings}`;
          addMessage("bot", summary);

          // Individual findings
          res.data.results.forEach((r) => {
            r.findings.forEach((f) => {
                const sev = (f.severity || "info").toLowerCase();
                addMessage(
                    "bot",
                    `[${sev.toUpperCase()}] ${f.title}\n\n${f.description}\n\n💡 ${f.remediation || "No remediation provided."}`,
                    "finding",
                    sev   // pass severity
                );
            });
            
          });
        }
      }
      // Answer / skip
      else {
        const res = await axios.post(`${API}/answer`, {
          session_id: sessionId,
          answer: text,
        });

        addMessage("bot", res.data.message);
        setStatus(res.data.status);

        if (res.data.questions?.length > 0) {
          res.data.questions.forEach((q) => addMessage("bot", q.question));
        } else if (res.data.status === "ready") {
          addMessage("bot", "Ready! Click **Run Scan** or type 'run'.");
        }
      }
    } catch (err) {
      console.error(err);
      const detail = err.response?.data?.detail;
      addMessage(
        "bot",
        typeof detail === "string"
          ? detail
          : "Something went wrong. Try again or start a new session."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const getFindingStyle = (severity) => {
  switch ((severity || "").toLowerCase()) {
    case "critical":
    case "high":
      return "bg-red-500/15 border border-red-500/30 text-red-100";
    case "medium":
      return "bg-orange-500/15 border border-orange-500/30 text-orange-100";
    case "low":
      return "bg-yellow-500/15 border border-yellow-500/30 text-yellow-100";
    default:
      return "bg-blue-500/10 border border-blue-500/20 text-gray-200";
  }
};

  const statusColor = {
    idle: "text-gray-400",
    collecting: "text-yellow-400",
    ready: "text-blue-400",
    running: "text-blue-400 animate-pulse",
    completed: "text-emerald-400",
  };

  return (
    <div className="flex flex-col h-[calc(100vh-120px)] max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="bg-emerald-500/10 p-2 rounded-lg">
            <Shield className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">AI Security Chat</h1>
            <p className="text-sm text-gray-400">
              One target → Automatic multi-vulnerability scan
            </p>
          </div>
        </div>

        <button
          onClick={resetChat}
          className="flex items-center gap-2 text-sm text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded-lg transition"
        >
          <RotateCcw className="w-4 h-4" />
          New Session
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-4 mb-4">
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
          >
            {msg.role === "bot" && (
              <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center flex-shrink-0 mt-1">
                <Bot className="w-4 h-4 text-emerald-400" />
              </div>
            )}

            <div
                className={`max-w-[85%] rounded-2xl px-4 py-3 text-sm whitespace-pre-wrap leading-relaxed ${
                    msg.role === "user"
                        ? "bg-emerald-600 text-white"
                        : msg.type === "finding"
                        ? getFindingStyle(msg.severity)
                        : "bg-gray-800 text-gray-200"
                }`}
            >
                {msg.text}
            </div>

            {msg.role === "user" && (
              <div className="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center flex-shrink-0 mt-1">
                <User className="w-4 h-4 text-gray-300" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <Bot className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="bg-gray-800 rounded-2xl px-4 py-3 text-sm text-gray-400">
              Working...
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Quick Actions */}
      {sessionId && status !== "running" && status !== "completed" && (
        <div className="flex gap-2 mb-3">
          <button
            onClick={() => handleSend("skip bola")}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded-lg transition"
          >
            <SkipForward className="w-3.5 h-3.5" />
            Skip BOLA
          </button>
          <button
            onClick={() => handleSend("run")}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 px-3 py-1.5 rounded-lg transition"
          >
            <Play className="w-3.5 h-3.5" />
            Run Scan
          </button>
        </div>
      )}

      {/* Input */}
      <div className="flex gap-3">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter target URL, or type run / skip bola..."
          disabled={loading}
          className="flex-1 bg-gray-900 border border-gray-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-emerald-500 disabled:opacity-50"
        />
        <button
          onClick={() => handleSend()}
          disabled={loading || !input.trim()}
          className="bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:cursor-not-allowed px-5 rounded-xl transition"
        >
          <Send className="w-5 h-5" />
        </button>
      </div>

      {/* Status bar */}
      <div className="mt-2 flex items-center justify-between text-xs text-gray-500">
        <div>
          Status:{" "}
          <span className={`font-medium capitalize ${statusColor[status] || "text-gray-400"}`}>
            {status}
          </span>
          {sessionId && (
            <span className="ml-3 text-gray-600">
              Session: {sessionId.slice(0, 8)}...
            </span>
          )}
        </div>
      </div>
    </div>
  );
}