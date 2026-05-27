import * as p from "@clack/prompts";

export function requirePromptValue<T>(
  value: T | symbol,
  message = "Setup cancelled.",
): T {
  if (p.isCancel(value)) {
    p.cancel(message);
    process.exit(0);
  }

  return value as T;
}
