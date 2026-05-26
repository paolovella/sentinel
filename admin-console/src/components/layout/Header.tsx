// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { LogOut, User } from "lucide-react";
import { useAuth } from "../../auth/authContext";

export function Header() {
  const { session, role, logout } = useAuth();

  return (
    <header className="header">
      <div className="header-left">
        <h2 className="header-title">Vellaveto Admin Console</h2>
      </div>
      <div className="header-right">
        <span className="role-badge" data-role={role}>
          {role}
        </span>
        {session?.subject && (
          <span className="user-info">
            <User size={14} />
            {session.subject}
          </span>
        )}
        <button className="btn btn--ghost" onClick={logout} title="Sign out">
          <LogOut size={16} />
        </button>
      </div>
    </header>
  );
}
