import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface DetectedTool {
  name: string;
  installed: boolean;
  config_path: string | null;
  mcp_servers: McpServer[];
  protected: boolean;
  risk_warnings: string[];
}

interface McpServer {
  name: string;
  command: string;
  args: string[];
  protected: boolean;
}

interface Notification {
  ts: string;
  tool: string;
  action: string;
  params_summary: string;
  verdict: string;
  reason: string;
  severity: string;
}

type View = "dashboard" | "activity" | "settings";

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [tools, setTools] = useState<DetectedTool[]>([]);
  const [level, setLevel] = useState("shield");
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    refreshTools();
    const interval = setInterval(pollNotifications, 3000);
    return () => clearInterval(interval);
  }, []);

  async function refreshTools() {
    try {
      const detected = await invoke<DetectedTool[]>("detect_tools");
      setTools(detected);
    } catch (e) {
      console.error("Failed to detect tools:", e);
    }
  }

  async function protectAll() {
    setLoading(true);
    try {
      const count = await invoke<number>("protect_all", { level });
      await refreshTools();
      alert(`Protected ${count} tool(s). Restart your AI tools for changes to take effect.`);
    } catch (e) {
      alert(`Error: ${e}`);
    }
    setLoading(false);
  }

  async function protectTool(configPath: string) {
    try {
      await invoke("protect_tool", { configPath, level });
      await refreshTools();
    } catch (e) {
      alert(`Error: ${e}`);
    }
  }

  async function unprotectTool(configPath: string) {
    try {
      await invoke("unprotect_tool", { configPath });
      await refreshTools();
    } catch (e) {
      alert(`Error: ${e}`);
    }
  }

  async function pollNotifications() {
    try {
      const newEvents = await invoke<Notification[]>("poll_notifications");
      if (newEvents.length > 0) {
        setNotifications((prev) => [...newEvents, ...prev].slice(0, 200));
      }
    } catch (_) {}
  }

  const installed = tools.filter((t) => t.installed);
  const unprotected = installed.filter((t) => !t.protected);
  const blocked = notifications.filter((n) => n.verdict === "Deny");
  const allowed = notifications.filter((n) => n.verdict === "Allow");

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold">
            <span className="text-purple-400">VellaVeto</span> — Protect Your AI Tools
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            {installed.length} tool{installed.length !== 1 ? "s" : ""} detected
            {unprotected.length > 0 && (
              <span className="text-yellow-400 ml-2">
                ({unprotected.length} unprotected)
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          {(["dashboard", "activity", "settings"] as View[]).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`px-3 py-1 rounded text-sm ${
                view === v
                  ? "bg-purple-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              {v.charAt(0).toUpperCase() + v.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Dashboard */}
      {view === "dashboard" && (
        <div>
          {/* Tool list */}
          <div className="space-y-3 mb-6">
            {tools.map((tool) => (
              <div
                key={tool.name}
                className="bg-gray-900 rounded-lg p-4 border border-gray-800"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span
                      className={`w-3 h-3 rounded-full ${
                        !tool.installed
                          ? "bg-gray-600"
                          : tool.protected
                          ? "bg-green-500"
                          : "bg-yellow-500"
                      }`}
                    />
                    <div>
                      <span className="font-medium">{tool.name}</span>
                      <span className="text-gray-500 text-sm ml-2">
                        {!tool.installed
                          ? "Not installed"
                          : tool.protected
                          ? "Protected"
                          : `${tool.mcp_servers.length} MCP server${tool.mcp_servers.length !== 1 ? "s" : ""}`}
                      </span>
                    </div>
                  </div>
                  {tool.installed && tool.config_path && (
                    <button
                      onClick={() =>
                        tool.protected
                          ? unprotectTool(tool.config_path!)
                          : protectTool(tool.config_path!)
                      }
                      className={`px-3 py-1 rounded text-sm ${
                        tool.protected
                          ? "bg-gray-700 text-gray-300 hover:bg-red-900 hover:text-red-300"
                          : "bg-purple-600 text-white hover:bg-purple-500"
                      }`}
                    >
                      {tool.protected ? "Unprotect" : "Protect"}
                    </button>
                  )}
                </div>
                {tool.risk_warnings.length > 0 && (
                  <div className="mt-2 text-sm text-yellow-400">
                    {tool.risk_warnings.map((w, i) => (
                      <div key={i}>{w}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Protection level */}
          <div className="bg-gray-900 rounded-lg p-4 border border-gray-800 mb-6">
            <div className="text-sm font-medium text-gray-400 mb-3">Protection Level</div>
            <div className="flex gap-3">
              {[
                { id: "shield", label: "Shield", desc: "Blocks dangerous stuff, allows rest" },
                { id: "fortress", label: "Fortress", desc: "Shield + more restrictions" },
                { id: "vault", label: "Vault", desc: "Block everything, ask permission" },
              ].map((l) => (
                <button
                  key={l.id}
                  onClick={() => setLevel(l.id)}
                  className={`flex-1 p-3 rounded-lg text-left ${
                    level === l.id
                      ? "bg-purple-900/50 border border-purple-500"
                      : "bg-gray-800 border border-gray-700 hover:border-gray-600"
                  }`}
                >
                  <div className="font-medium text-sm">{l.label}</div>
                  <div className="text-xs text-gray-500 mt-1">{l.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Protect All button */}
          {unprotected.length > 0 && (
            <button
              onClick={protectAll}
              disabled={loading}
              className="w-full py-3 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-700 rounded-lg font-medium text-lg"
            >
              {loading ? "Protecting..." : `Protect All (${unprotected.length})`}
            </button>
          )}

          {unprotected.length === 0 && installed.length > 0 && (
            <div className="text-center text-green-400 py-4">
              All detected AI tools are protected.
            </div>
          )}
        </div>
      )}

      {/* Activity Feed */}
      {view === "activity" && (
        <div>
          <div className="text-sm text-gray-500 mb-4">
            {allowed.length} allowed · {blocked.length} blocked
          </div>
          <div className="space-y-2">
            {notifications.length === 0 && (
              <div className="text-gray-600 text-center py-8">
                No activity yet. Use your AI tools and activity will appear here.
              </div>
            )}
            {notifications.map((n, i) => (
              <div
                key={i}
                className={`p-3 rounded-lg border ${
                  n.verdict === "Deny"
                    ? n.severity === "high"
                      ? "bg-red-950/30 border-red-800"
                      : "bg-yellow-950/30 border-yellow-800"
                    : "bg-gray-900 border-gray-800"
                }`}
              >
                <div className="flex items-center gap-2 text-sm">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      n.verdict === "Deny"
                        ? n.severity === "high"
                          ? "bg-red-500"
                          : "bg-yellow-500"
                        : "bg-green-500"
                    }`}
                  />
                  <span className="text-gray-400">{n.ts.slice(11, 19)}</span>
                  <span className="font-medium">{n.tool}</span>
                </div>
                <div className="ml-4 mt-1 text-sm">
                  <span className="text-gray-300">{n.action}</span>
                  {n.params_summary && (
                    <span className="text-gray-500">
                      ({n.params_summary.slice(0, 50)})
                    </span>
                  )}
                </div>
                {n.verdict === "Deny" && (
                  <div className="ml-4 mt-1 text-xs text-red-400">{n.reason}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Settings */}
      {view === "settings" && (
        <div className="space-y-6">
          <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
            <h3 className="font-medium mb-3">Protection Level</h3>
            <p className="text-sm text-gray-500">
              {level === "shield" && "Blocks credential theft, data exfiltration, config injection, and dangerous commands."}
              {level === "fortress" && "Shield + system file protection, package config tampering, privilege escalation approval."}
              {level === "vault" && "Maximum security. Deny-by-default. Only safe reads allowed."}
            </p>
          </div>

          <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
            <h3 className="font-medium mb-3">About</h3>
            <p className="text-sm text-gray-500">
              VellaVeto Desktop v0.1.0
            </p>
            <p className="text-sm text-gray-600 mt-1">
              Powered by vellaveto-proxy with 11,483+ tests and formal verification.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
