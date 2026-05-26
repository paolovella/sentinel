// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users, Pause } from "lucide-react";
import { DataTable, type Column } from "../components/common/DataTable";
import { useAuth } from "../auth/authContext";
import * as api from "../api/client";
import type { AgentInfo } from "../types/api";

export function AgentsPage() {
  const { role } = useAuth();
  const queryClient = useQueryClient();
  const canManage = role === "admin" || role === "operator";

  const agentsQ = useQuery({
    queryKey: ["agents"],
    queryFn: api.listAgents,
  });

  const suspendMut = useMutation({
    mutationFn: api.suspendAgent,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["agents"] }),
  });

  const columns: Column<AgentInfo>[] = [
    { key: "id", header: "Agent ID", width: "200px", render: (a) => <code>{a.id}</code> },
    { key: "name", header: "Name", render: (a) => a.name },
    {
      key: "status",
      header: "Status",
      width: "100px",
      render: (a) => (
        <span className={`status-badge status-badge--${a.status}`}>
          {a.status}
        </span>
      ),
    },
    {
      key: "credential",
      header: "Credential",
      width: "120px",
      render: (a) => a.credential_type ?? "none",
    },
    {
      key: "last_seen",
      header: "Last Seen",
      width: "160px",
      render: (a) =>
        a.last_seen ? new Date(a.last_seen).toLocaleString() : "never",
    },
    {
      key: "actions",
      header: "",
      width: "60px",
      render: (a) =>
        canManage && a.status === "active" ? (
          <button
            className="btn btn--ghost btn--danger"
            onClick={() => {
              if (confirm(`Suspend agent "${a.name}"?`)) {
                suspendMut.mutate(a.id);
              }
            }}
            title="Suspend agent"
          >
            <Pause size={14} />
          </button>
        ) : null,
    },
  ];

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <Users size={20} />
          Registered Agents
        </h2>
      </div>

      <DataTable
        columns={columns}
        data={agentsQ.data ?? []}
        keyFn={(a) => a.id}
        emptyMessage="No agents registered"
      />
    </div>
  );
}
