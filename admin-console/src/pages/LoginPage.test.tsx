// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { LoginPage } from "./LoginPage";

// Mock the auth provider
const mockLogin = vi.fn();
const mockSetApiKey = vi.fn();

vi.mock("../auth/authContext", () => ({
  useAuth: () => ({
    login: mockLogin,
    setApiKey: mockSetApiKey,
    authenticated: false,
    loading: false,
    session: null,
    role: "viewer",
    logout: vi.fn(),
  }),
}));

describe("LoginPage", () => {
  it("renders title", () => {
    render(<LoginPage />);
    expect(screen.getByText("Vellaveto Admin Console")).toBeInTheDocument();
  });

  it("renders SSO button", () => {
    render(<LoginPage />);
    expect(screen.getByText("Sign in with SSO")).toBeInTheDocument();
  });

  it("calls login on SSO button click", () => {
    render(<LoginPage />);
    fireEvent.click(screen.getByText("Sign in with SSO"));
    expect(mockLogin).toHaveBeenCalledOnce();
  });

  it("renders API key form", () => {
    render(<LoginPage />);
    expect(screen.getByPlaceholderText("API Key")).toBeInTheDocument();
    expect(screen.getByText("Connect with API Key")).toBeInTheDocument();
  });

  it("disables submit when key is empty", () => {
    render(<LoginPage />);
    const btn = screen.getByText("Connect with API Key");
    expect(btn).toBeDisabled();
  });

  it("enables submit when key is entered", () => {
    render(<LoginPage />);
    const input = screen.getByPlaceholderText("API Key");
    fireEvent.change(input, { target: { value: "test-key-123" } });
    const btn = screen.getByText("Connect with API Key");
    expect(btn).not.toBeDisabled();
  });

  it("calls setApiKey on form submit", () => {
    render(<LoginPage />);
    const input = screen.getByPlaceholderText("API Key");
    fireEvent.change(input, { target: { value: "my-secret-key" } });
    fireEvent.submit(input.closest("form")!);
    expect(mockSetApiKey).toHaveBeenCalledWith("my-secret-key");
  });

  it("trims whitespace from API key", () => {
    render(<LoginPage />);
    const input = screen.getByPlaceholderText("API Key");
    fireEvent.change(input, { target: { value: "  key-with-spaces  " } });
    fireEvent.submit(input.closest("form")!);
    expect(mockSetApiKey).toHaveBeenCalledWith("key-with-spaces");
  });
});
