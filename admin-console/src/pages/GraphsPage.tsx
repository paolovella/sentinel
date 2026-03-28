// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Network } from "lucide-react";
import * as api from "../api/client";

export function GraphsPage() {
  const [selected, setSelected] = useState<string | null>(null);

  const sessionsQ = useQuery({
    queryKey: ["graph-sessions"],
    queryFn: api.listGraphSessions,
  });

  const svgQ = useQuery({
    queryKey: ["graph-svg", selected],
    queryFn: () => api.getGraphSvg(selected!),
    enabled: selected !== null,
  });

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <Network size={20} />
          Execution Graphs
        </h2>
      </div>

      <div className="graph-layout">
        <div className="graph-sessions">
          <h3 className="section-title">Sessions</h3>
          {(sessionsQ.data ?? []).length === 0 ? (
            <div className="empty-state">No execution graphs recorded</div>
          ) : (
            <ul className="session-list">
              {(sessionsQ.data ?? []).map((s) => (
                <li key={s}>
                  <button
                    className={`session-item ${s === selected ? "session-item--active" : ""}`}
                    onClick={() => setSelected(s)}
                  >
                    <code>{s.slice(0, 16)}...</code>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="graph-viewer">
          {selected === null ? (
            <div className="empty-state">Select a session to view its graph</div>
          ) : svgQ.isLoading ? (
            <div className="empty-state">Loading graph...</div>
          ) : svgQ.data ? (
            // SECURITY (R257-CONSOLE-1): Render SVG as <img> data URI to prevent
            // stored XSS — <img> SVG rendering never executes scripts.
            <img
              className="svg-container"
              src={`data:image/svg+xml;base64,${btoa(svgQ.data)}`}
              alt="Execution graph"
            />
          ) : (
            <div className="empty-state">Failed to load graph</div>
          )}
        </div>
      </div>
    </div>
  );
}
