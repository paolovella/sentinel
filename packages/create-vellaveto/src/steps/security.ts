import * as p from "@clack/prompts";
import pc from "picocolors";
import { requirePromptValue } from "../prompt.js";
import type { WizardState } from "../types.js";
import { generateApiKey, isValidOrigin } from "../utils.js";

export async function securityStep(
  state: WizardState,
): Promise<void> {
  const generatedKey = generateApiKey();

  p.log.info(`Generated API key: ${pc.cyan(generatedKey)}`);

  const useGenerated = requirePromptValue(await p.confirm({
    message: "Use this API key?",
    initialValue: true,
  }));

  if (useGenerated) {
    state.apiKey = generatedKey;
  } else {
    const customKey = requirePromptValue(await p.text({
      message: "Enter your API key",
      validate(value) {
        if (!value || value.length < 8) return "API key must be at least 8 characters";
      },
    }));

    state.apiKey = customKey;
  }

  const corsInput = requirePromptValue(await p.text({
    message: "Allowed CORS origins (comma-separated, or * for all)",
    placeholder: "http://localhost:3000",
    defaultValue: "",
  }));

  if (corsInput.trim()) {
    const origins = corsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const invalid = origins.filter((o) => !isValidOrigin(o));
    if (invalid.length > 0) {
      p.log.warn(
        `Skipping invalid origins: ${invalid.join(", ")}`,
      );
    }
    state.corsOrigins = origins.filter((o) => isValidOrigin(o));
  }

  const anonymous = requirePromptValue(await p.confirm({
    message: "Allow anonymous (unauthenticated) evaluate requests?",
    initialValue: false,
  }));

  state.anonymousMode = anonymous;
}
