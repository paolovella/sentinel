// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { createContext, useContext } from "react";
import type { Role, UserSession } from "../types/api";

export interface AuthState {
  authenticated: boolean;
  loading: boolean;
  session: UserSession | null;
  role: Role;
  login: () => void;
  logout: () => void;
  setApiKey: (key: string) => void;
}

export const AuthContext = createContext<AuthState>({
  authenticated: false,
  loading: true,
  session: null,
  role: "viewer",
  login: () => {},
  logout: () => {},
  setApiKey: () => {},
});

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
