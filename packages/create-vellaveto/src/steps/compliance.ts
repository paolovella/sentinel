import * as p from "@clack/prompts";
import { requirePromptValue } from "../prompt.js";
import type { ComplianceFramework, WizardState } from "../types.js";

const FRAMEWORKS: { value: ComplianceFramework; label: string; hint: string }[] = [
  { value: "eu_ai_act", label: "EU AI Act", hint: "Transparency marking, risk assessment" },
  { value: "nis2", label: "NIS2", hint: "Incident reporting, supply chain checks" },
  { value: "dora", label: "DORA", hint: "ICT risk management, incident tracking" },
  { value: "soc2", label: "SOC 2", hint: "Trust service criteria auditing" },
  { value: "iso42001", label: "ISO 42001", hint: "AI management system standard" },
];

export async function complianceStep(
  state: WizardState,
): Promise<void> {
  p.log.info("Select which compliance frameworks to enable:");

  const selected: ComplianceFramework[] = [];

  for (const fw of FRAMEWORKS) {
    const enabled = requirePromptValue(await p.confirm({
      message: `${fw.label} — ${fw.hint}`,
      initialValue: false,
    }));

    if (enabled) {
      selected.push(fw.value);
    }
  }

  state.complianceFrameworks = selected;
}
