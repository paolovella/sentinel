// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import type { Verdict } from "../../types/api";
import { verdictClass, verdictLabel } from "./verdict";

interface Props {
  verdict: Verdict;
}

export function VerdictBadge({ verdict }: Props) {
  return (
    <span className={`verdict-badge ${verdictClass(verdict)}`}>
      {verdictLabel(verdict)}
    </span>
  );
}
