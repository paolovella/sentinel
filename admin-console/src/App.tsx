// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { BrowserRouter, Routes, Route, Navigate } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "./auth/AuthProvider";
import { useAuth } from "./auth/authContext";
import { Layout } from "./components/layout/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { AuditPage } from "./pages/AuditPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { AgentsPage } from "./pages/AgentsPage";
import { CompliancePage } from "./pages/CompliancePage";
import { GovernancePage } from "./pages/GovernancePage";
import { GraphsPage } from "./pages/GraphsPage";
import { BillingPage } from "./pages/BillingPage";
import { SettingsPage } from "./pages/SettingsPage";
import { LoginPage } from "./pages/LoginPage";
import type { ReactNode } from "react";
import "./App.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5_000,
      refetchOnWindowFocus: true,
    },
  },
});

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { authenticated, loading } = useAuth();
  if (loading) return <div className="loading-screen">Loading...</div>;
  if (!authenticated) return <LoginPage />;
  return <>{children}</>;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route index element={<DashboardPage />} />
              <Route path="audit" element={<AuditPage />} />
              <Route path="policies" element={<PoliciesPage />} />
              <Route path="approvals" element={<ApprovalsPage />} />
              <Route path="agents" element={<AgentsPage />} />
              <Route path="compliance" element={<CompliancePage />} />
              <Route path="governance" element={<GovernancePage />} />
              <Route path="graphs" element={<GraphsPage />} />
              <Route path="billing" element={<BillingPage />} />
              <Route path="settings" element={<SettingsPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}
