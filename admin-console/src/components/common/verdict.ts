// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import type { Verdict } from "../../types/api";

export function verdictLabel(v: Verdict): string {
  if (v === "Allow") return "Allow";
  if ("Deny" in v) return "Deny";
  if ("RequireApproval" in v) return "Approval";
  return "Unknown";
}

export function verdictClass(v: Verdict): string {
  if (v === "Allow") return "verdict--allow";
  if ("Deny" in v) return "verdict--deny";
  return "verdict--approval";
}
