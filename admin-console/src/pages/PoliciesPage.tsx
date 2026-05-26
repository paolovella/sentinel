// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, Trash2, RefreshCw, Plus } from "lucide-react";
import { DataTable, type Column } from "../components/common/DataTable";
import { useAuth } from "../auth/authContext";
import * as api from "../api/client";
import type { Policy } from "../types/api";

export function PoliciesPage() {
  const { role } = useAuth();
  const queryClient = useQueryClient();
  const canWrite = role === "admin" || role === "operator";

  const policiesQ = useQuery({
    queryKey: ["policies"],
    queryFn: api.listPolicies,
  });

  const reloadMut = useMutation({
    mutationFn: api.reloadPolicies,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["policies"] }),
  });

  const deleteMut = useMutation({
    mutationFn: api.deletePolicy,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["policies"] }),
  });

  const columns: Column<Policy>[] = [
    { key: "id", header: "ID", width: "200px", render: (p) => <code>{p.id}</code> },
    { key: "name", header: "Name", render: (p) => p.name },
    {
      key: "type",
      header: "Type",
      width: "140px",
      render: (p) => {
        const t = typeof p.policy_type === "string" ? p.policy_type : "Conditional";
        return <span className={`policy-type policy-type--${t.toLowerCase()}`}>{t}</span>;
      },
    },
    { key: "priority", header: "Priority", width: "80px", render: (p) => p.priority },
    {
      key: "actions",
      header: "",
      width: "60px",
      render: (p) =>
        canWrite ? (
          <button
            className="btn btn--ghost btn--danger"
            onClick={() => {
              if (confirm(`Delete policy "${p.name}"?`)) {
                deleteMut.mutate(p.id);
              }
            }}
            title="Delete policy"
          >
            <Trash2 size={14} />
          </button>
        ) : null,
    },
  ];

  return (
    <div className="page">
      <div className="page-header">
        <h2 className="page-title">
          <FileText size={20} />
          Policies
        </h2>
        <div className="page-actions">
          {canWrite && (
            <button className="btn btn--primary" disabled>
              <Plus size={16} />
              New Policy
            </button>
          )}
          <button
            className="btn btn--outline"
            onClick={() => reloadMut.mutate()}
            disabled={reloadMut.isPending}
          >
            <RefreshCw size={16} />
            Reload
          </button>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={policiesQ.data ?? []}
        keyFn={(p) => p.id}
        emptyMessage="No policies configured"
      />
    </div>
  );
}
