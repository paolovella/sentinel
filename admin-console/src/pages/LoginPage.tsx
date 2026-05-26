// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { useAuth } from "../auth/authContext";

export function LoginPage() {
  const { login, setApiKey } = useAuth();
  const [key, setKey] = useState("");

  return (
    <div className="login-page">
      <div className="login-card">
        <h1 className="login-title">Vellaveto Admin Console</h1>
        <p className="login-subtitle">
          Sign in with your identity provider or enter an API key.
        </p>

        <button className="btn btn--primary btn--full" onClick={login}>
          Sign in with SSO
        </button>

        <div className="login-divider">
          <span>or</span>
        </div>

        <form
          className="login-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (key.trim()) setApiKey(key.trim());
          }}
        >
          <input
            type="password"
            className="input input--full"
            placeholder="API Key"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            autoComplete="off"
          />
          <button
            type="submit"
            className="btn btn--outline btn--full"
            disabled={!key.trim()}
          >
            Connect with API Key
          </button>
        </form>
      </div>
    </div>
  );
}
