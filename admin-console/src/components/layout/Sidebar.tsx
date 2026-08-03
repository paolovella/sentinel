// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { NavLink } from "react-router";
import {
  LayoutDashboard,
  ScrollText,
  ShieldCheck,
  Users,
  FileText,
  AlertTriangle,
  Activity,
  Settings,
  CreditCard,
  Network,
} from "lucide-react";
import { useAuth } from "../../auth/authContext";
import type { Role } from "../../types/api";

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  minRole: Role;
}

const roleLevel: Record<Role, number> = {
  viewer: 0,
  auditor: 1,
  operator: 2,
  admin: 3,
};

function hasAccess(userRole: Role, minRole: Role): boolean {
  return roleLevel[userRole] >= roleLevel[minRole];
}

const navItems: NavItem[] = [
  { path: "/", label: "Dashboard", icon: <LayoutDashboard size={18} />, minRole: "viewer" },
  { path: "/audit", label: "Audit Log", icon: <ScrollText size={18} />, minRole: "auditor" },
  { path: "/policies", label: "Policies", icon: <FileText size={18} />, minRole: "viewer" },
  { path: "/approvals", label: "Approvals", icon: <ShieldCheck size={18} />, minRole: "operator" },
  { path: "/agents", label: "Agents", icon: <Users size={18} />, minRole: "viewer" },
  { path: "/compliance", label: "Compliance", icon: <Activity size={18} />, minRole: "auditor" },
  { path: "/governance", label: "Governance", icon: <AlertTriangle size={18} />, minRole: "operator" },
  { path: "/graphs", label: "Exec Graphs", icon: <Network size={18} />, minRole: "viewer" },
  { path: "/billing", label: "Billing", icon: <CreditCard size={18} />, minRole: "admin" },
  { path: "/settings", label: "Settings", icon: <Settings size={18} />, minRole: "admin" },
];

export function Sidebar() {
  const { role } = useAuth();

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-brand">
          <img src="/favicon.svg" alt="Vellaveto" width={28} height={28} className="sidebar-logo" />
          <div>
            <h1 className="sidebar-title">Vellaveto</h1>
            <span className="sidebar-subtitle">Admin Console</span>
          </div>
        </div>
      </div>
      <nav className="sidebar-nav">
        {navItems
          .filter((item) => hasAccess(role, item.minRole))
          .map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === "/"}
              className={({ isActive }) =>
                `nav-link ${isActive ? "nav-link--active" : ""}`
              }
            >
              {item.icon}
              <span>{item.label}</span>
            </NavLink>
          ))}
      </nav>
    </aside>
  );
}
