import * as p from "@clack/prompts";
import { requirePromptValue } from "../prompt.js";
import type { WizardState } from "../types.js";

export async function detectionStep(
  state: WizardState,
): Promise<void> {
  const injectionEnabled = requirePromptValue(await p.confirm({
    message: "Enable injection detection?",
    initialValue: true,
  }));
  state.injectionEnabled = injectionEnabled;

  if (injectionEnabled) {
    const injectionBlocking = requirePromptValue(await p.confirm({
      message: "Block requests with detected injections? (vs. log-only)",
      initialValue: false,
    }));
    state.injectionBlocking = injectionBlocking;
  }

  const dlpEnabled = requirePromptValue(await p.confirm({
    message: "Enable DLP (Data Loss Prevention) scanning?",
    initialValue: true,
  }));
  state.dlpEnabled = dlpEnabled;

  if (dlpEnabled) {
    const dlpBlocking = requirePromptValue(await p.confirm({
      message: "Block requests with DLP findings? (vs. log-only)",
      initialValue: false,
    }));
    state.dlpBlocking = dlpBlocking;
  }

  const behavioralEnabled = requirePromptValue(await p.confirm({
    message: "Enable behavioral anomaly detection?",
    initialValue: false,
  }));
  state.behavioralEnabled = behavioralEnabled;
}
