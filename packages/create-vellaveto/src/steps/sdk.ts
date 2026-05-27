import * as p from "@clack/prompts";
import pc from "picocolors";
import { requirePromptValue } from "../prompt.js";
import type { SdkLanguage, WizardState } from "../types.js";
import { generateSnippet, installCommand } from "../generators/snippets.js";

export async function sdkStep(
  state: WizardState,
): Promise<void> {
  const language = requirePromptValue(await p.select<SdkLanguage>({
    message: "Show integration snippet for which SDK?",
    options: [
      { value: "python", label: "Python", hint: "pip install vellaveto" },
      { value: "typescript", label: "TypeScript", hint: "npm install vellaveto" },
      { value: "go", label: "Go", hint: "go get vellaveto" },
      { value: "java", label: "Java", hint: "Maven / Gradle" },
      { value: "skip", label: "Skip", hint: "No snippet needed" },
    ],
  }));

  state.sdkLanguage = language;

  if (language !== "skip") {
    const install = installCommand(language);
    const snippet = generateSnippet(language, state.apiKey);
    p.note(
      `${pc.dim("Install:")}\n${install}\n\n${pc.dim("Usage:")}\n${snippet}`,
      `${language.charAt(0).toUpperCase() + language.slice(1)} SDK`,
    );
  }
}
