// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { VerdictBadge } from "./VerdictBadge";
import { verdictClass, verdictLabel } from "./verdict";

describe("verdictLabel", () => {
  it("returns 'Allow' for Allow verdict", () => {
    expect(verdictLabel("Allow")).toBe("Allow");
  });

  it("returns 'Deny' for Deny verdict", () => {
    expect(verdictLabel({ Deny: { reason: "blocked" } })).toBe("Deny");
  });

  it("returns 'Approval' for RequireApproval verdict", () => {
    expect(
      verdictLabel({ RequireApproval: { reason: "needs human" } }),
    ).toBe("Approval");
  });
});

describe("verdictClass", () => {
  it("returns allow class for Allow", () => {
    expect(verdictClass("Allow")).toBe("verdict--allow");
  });

  it("returns deny class for Deny", () => {
    expect(verdictClass({ Deny: { reason: "x" } })).toBe("verdict--deny");
  });

  it("returns approval class for RequireApproval", () => {
    expect(verdictClass({ RequireApproval: { reason: "y" } })).toBe(
      "verdict--approval",
    );
  });
});

describe("VerdictBadge component", () => {
  it("renders Allow badge", () => {
    render(<VerdictBadge verdict="Allow" />);
    expect(screen.getByText("Allow")).toBeInTheDocument();
  });

  it("renders Deny badge", () => {
    render(
      <VerdictBadge verdict={{ Deny: { reason: "policy violation" } }} />,
    );
    expect(screen.getByText("Deny")).toBeInTheDocument();
  });

  it("renders Approval badge", () => {
    render(
      <VerdictBadge verdict={{ RequireApproval: { reason: "high risk" } }} />,
    );
    expect(screen.getByText("Approval")).toBeInTheDocument();
  });

  it("applies correct CSS class for Allow", () => {
    const { container } = render(<VerdictBadge verdict="Allow" />);
    expect(container.firstChild).toHaveClass("verdict--allow");
  });

  it("applies correct CSS class for Deny", () => {
    const { container } = render(
      <VerdictBadge verdict={{ Deny: { reason: "x" } }} />,
    );
    expect(container.firstChild).toHaveClass("verdict--deny");
  });
});
