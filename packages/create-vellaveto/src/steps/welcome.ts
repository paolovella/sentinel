import * as p from "@clack/prompts";
import pc from "picocolors";
import { requirePromptValue } from "../prompt.js";
import type { DeploymentTarget, WizardState } from "../types.js";
import { BANNER } from "../constants.js";

export async function welcomeStep(
  state: WizardState,
  projectDir: string | undefined,
): Promise<string> {
  p.intro(pc.cyan(BANNER));

  p.note(
    "This wizard generates configuration files for Vellaveto,\n" +
      "the MCP policy gateway. No server required — just answer\n" +
      "a few questions and we'll create everything you need.",
    "Welcome",
  );

  // Ask for project directory if not provided via CLI arg
  let dir = projectDir;
  if (!dir) {
    const input = requirePromptValue(await p.text({
      message: "Project directory",
      placeholder: "vellaveto",
      defaultValue: "vellaveto",
    }));

    dir = input;
  }

  const target = requirePromptValue(await p.select<DeploymentTarget>({
    message: "How will you deploy Vellaveto?",
    options: [
      {
        value: "docker",
        label: "Docker Compose",
        hint: "docker-compose.yml + .env + vellaveto.toml",
      },
      {
        value: "binary",
        label: "Pre-built binary",
        hint: "Downloads binary + vellaveto.toml — ready to run",
      },
      {
        value: "kubernetes",
        label: "Kubernetes / Helm",
        hint: "values.yaml + configmap + vellaveto.toml",
      },
      {
        value: "source",
        label: "Build from source",
        hint: "Clones repo + vellaveto.toml — cargo build",
      },
    ],
  }));

  state.deploymentTarget = target;
  return dir;
}
