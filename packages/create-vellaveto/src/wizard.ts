/**
 * Wizard orchestrator — runs all steps in sequence, generates files,
 * shows a summary, and writes output to disk.
 */

import { existsSync, writeFileSync, mkdirSync, chmodSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import * as p from "@clack/prompts";
import pc from "picocolors";
import type { WizardState, GeneratedFile } from "./types.js";
import { VERSION } from "./constants.js";
import { generateToml } from "./generators/toml.js";
import { generateDockerFiles } from "./generators/docker.js";
import { generateHelmFiles } from "./generators/helm.js";
import { generateBinaryFiles } from "./generators/binary.js";
import { welcomeStep } from "./steps/welcome.js";
import { securityStep } from "./steps/security.js";
import { policiesStep } from "./steps/policies.js";
import { detectionStep } from "./steps/detection.js";
import { auditStep } from "./steps/audit.js";
import { complianceStep } from "./steps/compliance.js";
import { sdkStep } from "./steps/sdk.js";

const REPO_URL = "https://github.com/paolovella/vellaveto.git";

function createDefaultState(): WizardState {
  return {
    deploymentTarget: "docker",
    apiKey: "",
    corsOrigins: [],
    anonymousMode: false,
    policyPreset: "balanced",
    injectionEnabled: true,
    injectionBlocking: false,
    dlpEnabled: true,
    dlpBlocking: false,
    behavioralEnabled: false,
    redactionLevel: "low",
    auditExportFormat: "none",
    auditExportTarget: "",
    checkpointInterval: 300,
    complianceFrameworks: [],
    sdkLanguage: "skip",
  };
}

export async function runWizard(projectDir: string | undefined): Promise<void> {
  const state = createDefaultState();

  // Step 1: Welcome + deployment target + project directory
  const dir = await welcomeStep(state, projectDir);
  const absDir = resolve(dir);

  // Check if directory exists and is non-empty
  if (existsSync(absDir)) {
    try {
      const entries = readdirSync(absDir);
      if (entries.length > 0) {
        const overwrite = await p.confirm({
          message: `Directory ${pc.cyan(absDir)} already exists and is not empty. Continue?`,
          initialValue: false,
        });
        if (p.isCancel(overwrite) || !overwrite) {
          p.cancel("Setup cancelled.");
          process.exit(0);
        }
      }
    } catch {
      // Can't read — will fail at write time
    }
  }

  // Step 2: Security
  await securityStep(state);

  // Step 3: Policies
  await policiesStep(state);

  // Step 4: Detection
  await detectionStep(state);

  // Step 5: Audit
  await auditStep(state);

  // Step 6: Compliance
  await complianceStep(state);

  // Step 7: SDK
  await sdkStep(state);

  // Step 8: Review + write
  const files = collectFiles(state);
  showSummary(state, files, absDir);

  const toml = generateToml(state);
  p.note(toml, "vellaveto.toml preview");

  const confirmed = await p.confirm({
    message: `Write ${files.length} file(s) to ${pc.cyan(absDir)}?`,
  });

  if (p.isCancel(confirmed) || !confirmed) {
    p.cancel("No files written.");
    process.exit(0);
  }

  writeFiles(files, absDir);
  addGitignore(absDir);

  p.outro(
    pc.green("Setup complete!") +
      "\n\n" +
      nextSteps(state, absDir),
  );
}

function collectFiles(state: WizardState): GeneratedFile[] {
  const files: GeneratedFile[] = [];

  // Always generate vellaveto.toml
  files.push({
    path: "vellaveto.toml",
    content: generateToml(state),
    description: "Vellaveto configuration file",
  });

  // Target-specific files
  switch (state.deploymentTarget) {
    case "docker":
      files.push(...generateDockerFiles(state));
      break;
    case "kubernetes":
      files.push(...generateHelmFiles(state));
      break;
    case "binary":
      files.push(...generateBinaryFiles(state));
      break;
    case "source":
      // Only vellaveto.toml
      break;
  }

  return files;
}

function showSummary(state: WizardState, files: GeneratedFile[], absDir: string): void {
  const lines: string[] = [];
  lines.push(`${pc.dim("Directory:")}     ${absDir}`);
  lines.push(`${pc.dim("Deployment:")}    ${state.deploymentTarget}`);
  lines.push(`${pc.dim("Policy:")}        ${state.policyPreset}`);
  lines.push(
    `${pc.dim("Injection:")}     ${state.injectionEnabled ? (state.injectionBlocking ? "blocking" : "log-only") : "disabled"}`,
  );
  lines.push(
    `${pc.dim("DLP:")}           ${state.dlpEnabled ? (state.dlpBlocking ? "blocking" : "log-only") : "disabled"}`,
  );
  lines.push(
    `${pc.dim("Behavioral:")}    ${state.behavioralEnabled ? "enabled" : "disabled"}`,
  );
  lines.push(`${pc.dim("Redaction:")}     ${state.redactionLevel}`);
  lines.push(`${pc.dim("Audit export:")}  ${state.auditExportFormat}`);
  if (state.complianceFrameworks.length > 0) {
    lines.push(
      `${pc.dim("Compliance:")}    ${state.complianceFrameworks.join(", ")}`,
    );
  }
  lines.push("");
  lines.push(pc.dim("Files to write:"));
  for (const f of files) {
    lines.push(`  ${pc.cyan(f.path)} — ${f.description}`);
  }

  p.note(lines.join("\n"), "Summary");
}

function writeFiles(files: GeneratedFile[], absDir: string): void {
  for (const file of files) {
    const absPath = resolve(absDir, file.path);
    mkdirSync(dirname(absPath), { recursive: true });
    writeFileSync(absPath, file.content, "utf-8");

    // Make shell scripts executable
    if (file.path.endsWith(".sh")) {
      chmodSync(absPath, 0o755);
    }

    p.log.success(`${pc.green("wrote")} ${file.path}`);
  }
}

/**
 * Add a .gitignore to protect secrets from accidental commits.
 */
function addGitignore(absDir: string): void {
  const gitignorePath = resolve(absDir, ".gitignore");
  if (!existsSync(gitignorePath)) {
    writeFileSync(
      gitignorePath,
      "# Vellaveto — do not commit secrets\n.env\n",
      "utf-8",
    );
    p.log.success(`${pc.green("wrote")} .gitignore`);
  }
}

function nextSteps(state: WizardState, absDir: string): string {
  const lines: string[] = [];
  lines.push(pc.bold("Next steps:"));
  lines.push("");

  switch (state.deploymentTarget) {
    case "docker":
      lines.push(`  cd ${absDir}`);
      lines.push("  docker compose up -d");
      lines.push("  curl http://localhost:3000/health");
      break;

    case "binary":
      lines.push(`  cd ${absDir}`);
      lines.push("  bash setup.sh");
      lines.push(
        `  VELLAVETO_API_KEY='${state.apiKey}' ./bin/vellaveto serve --config vellaveto.toml --open`,
      );
      break;

    case "kubernetes":
      lines.push(
        `  kubectl create secret generic vellaveto-api-key \\`,
      );
      lines.push(
        `    --from-literal=api-key='${state.apiKey}'`,
      );
      lines.push(`  kubectl apply -f ${absDir}/vellaveto-configmap.yaml`);
      lines.push(
        `  helm install vellaveto oci://ghcr.io/paolovella/vellaveto/chart \\`,
      );
      lines.push(
        `    -f ${absDir}/vellaveto-values.yaml`,
      );
      break;

    case "source":
      lines.push(`  git clone ${REPO_URL} vellaveto-src`);
      lines.push("  cd vellaveto-src");
      lines.push("  cargo build --release");
      lines.push(
        `  VELLAVETO_API_KEY='${state.apiKey}' \\`,
      );
      lines.push(
        `    ./target/release/vellaveto serve --config ${absDir}/vellaveto.toml --open`,
      );
      break;
  }

  lines.push("");
  lines.push(pc.dim("Documentation: https://github.com/paolovella/vellaveto"));

  return lines.join("\n");
}
