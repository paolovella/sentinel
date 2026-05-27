import * as p from "@clack/prompts";
import { requirePromptValue } from "../prompt.js";
import type { AuditExportFormat, RedactionLevel, WizardState } from "../types.js";

export async function auditStep(
  state: WizardState,
): Promise<void> {
  const redaction = requirePromptValue(await p.select<RedactionLevel>({
    message: "Audit log redaction level",
    options: [
      {
        value: "off",
        label: "Off",
        hint: "No redaction — full parameters logged (dev only)",
      },
      {
        value: "low",
        label: "Low (recommended)",
        hint: "Redact known secrets (API keys, tokens)",
      },
      {
        value: "high",
        label: "High",
        hint: "Redact all parameter values",
      },
    ],
    initialValue: "low",
  }));

  state.redactionLevel = redaction;

  const format = requirePromptValue(await p.select<AuditExportFormat>({
    message: "Audit export format",
    options: [
      {
        value: "none",
        label: "None",
        hint: "Local file logging only",
      },
      {
        value: "jsonl",
        label: "JSONL",
        hint: "JSON Lines — one event per line",
      },
      {
        value: "cef",
        label: "CEF",
        hint: "Common Event Format — for SIEM integration",
      },
      {
        value: "webhook",
        label: "Webhook",
        hint: "POST events to an HTTP endpoint",
      },
    ],
  }));

  state.auditExportFormat = format;

  if (format === "webhook") {
    const target = requirePromptValue(await p.text({
      message: "Webhook URL",
      placeholder: "https://example.com/vellaveto-events",
      validate(value) {
        if (!value) return "URL is required";
        try {
          const url = new URL(value);
          if (url.protocol !== "https:" && url.protocol !== "http:") {
            return "URL must use http:// or https://";
          }
        } catch {
          return "Please enter a valid URL";
        }
      },
    }));

    state.auditExportTarget = target;
  } else if (format === "jsonl" || format === "cef") {
    const target = requirePromptValue(await p.text({
      message: "Export file path",
      placeholder: `/var/log/vellaveto/export.${format}`,
      defaultValue: `/var/log/vellaveto/export.${format}`,
    }));

    state.auditExportTarget = target;
  }

  const checkpoint = requirePromptValue(await p.text({
    message: "Audit checkpoint interval (seconds, 0 to disable)",
    placeholder: "300",
    defaultValue: "300",
    validate(value) {
      const n = Number(value);
      if (isNaN(n) || n < 0 || !Number.isInteger(n)) {
        return "Must be a non-negative integer";
      }
    },
  }));

  state.checkpointInterval = Number(checkpoint);
}
