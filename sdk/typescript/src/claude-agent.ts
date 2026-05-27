/**
 * Anthropic Claude Agent SDK integration for Vellaveto.
 *
 * Provides tool permission enforcement hooks for Claude Agent SDK
 * applications in TypeScript. Evaluates tool calls against Vellaveto
 * policies before execution.
 *
 * @example
 * ```ts
 * import { VellavetoClient } from "vellaveto";
 * import { VellavetoToolPermission } from "vellaveto/claude-agent";
 *
 * const client = new VellavetoClient({ baseUrl: "http://localhost:3000" });
 * const permission = new VellavetoToolPermission(client);
 *
 * // Use as tool permission callback
 * const agent = new Agent({
 *   tools: [readFile, webSearch],
 *   toolPermissionCallback: (name, args) => permission.check(name, args),
 * });
 * ```
 */

import { VellavetoClient, PolicyDenied, ApprovalRequired } from "./client";
import { EvaluationContext, Verdict } from "./types";

const PATH_KEYS = new Set([
  "path", "file", "filepath", "file_path", "filename", "directory",
  "dir", "folder", "src", "dst", "source", "destination", "output",
  "input", "location", "target",
]);

const DOMAIN_KEYS = new Set([
  "url", "uri", "endpoint", "host", "domain", "api_url", "base_url",
  "webhook_url", "server", "address",
]);

const MAX_CALL_CHAIN = 20;
const MAX_FIELD_LENGTH = 256;
const MAX_TARGETS = 100;

/** Options for VellavetoToolPermission. */
export interface ToolPermissionOptions {
  /** Session identifier for audit correlation. */
  sessionId?: string;
  /** Agent identifier. */
  agentId?: string;
  /** Tenant identifier. */
  tenantId?: string;
  /** Deny on evaluation errors (default: true, fail-closed). */
  denyOnError?: boolean;
  /** Additional metadata for evaluation context. */
  metadata?: Record<string, unknown>;
}

/**
 * Tool permission callback for Claude Agent SDK.
 *
 * Integrates with the Claude Agent SDK's `toolPermissionCallback` parameter.
 * Each tool invocation is evaluated against Vellaveto policies.
 */
export class VellavetoToolPermission {
  private readonly client: VellavetoClient;
  private readonly sessionId?: string;
  private readonly agentId?: string;
  private readonly tenantId?: string;
  private readonly denyOnError: boolean;
  private readonly metadata: Record<string, unknown>;
  private callChain: string[] = [];

  constructor(client: VellavetoClient, options: ToolPermissionOptions = {}) {
    this.client = client;
    this.sessionId = options.sessionId;
    this.agentId = options.agentId;
    this.tenantId = options.tenantId;
    this.denyOnError = options.denyOnError ?? true;
    this.metadata = options.metadata ?? {};
  }

  private appendChain(entry: string): void {
    this.callChain.push(entry.slice(0, MAX_FIELD_LENGTH));
    if (this.callChain.length > MAX_CALL_CHAIN) {
      this.callChain = this.callChain.slice(-MAX_CALL_CHAIN);
    }
  }

  private buildContext(agentName?: string): EvaluationContext {
    const meta: Record<string, unknown> = { ...this.metadata, sdk: "claude_agent_sdk" };
    if (agentName) {
      meta.claude_agent_name = agentName.slice(0, MAX_FIELD_LENGTH);
    }
    return {
      session_id: this.sessionId,
      agent_id: this.agentId,
      tenant_id: this.tenantId,
      call_chain: [...this.callChain],
      metadata: meta,
    };
  }

  private extractTargets(params: Record<string, unknown>): {
    paths: string[];
    domains: string[];
  } {
    const paths: string[] = [];
    const domains: string[] = [];

    for (const [key, value] of Object.entries(params)) {
      if (typeof value !== "string") continue;
      const k = key.toLowerCase();
      if (PATH_KEYS.has(k)) {
        paths.push(value);
      } else if (DOMAIN_KEYS.has(k)) {
        domains.push(value);
      } else if (
        value.startsWith("http://") ||
        value.startsWith("https://") ||
        value.startsWith("ftp://")
      ) {
        domains.push(value);
      } else if (value.startsWith("file://")) {
        paths.push(value);
      }
    }

    return {
      paths: paths.slice(0, MAX_TARGETS),
      domains: domains.slice(0, MAX_TARGETS),
    };
  }

  /**
   * Check tool permission against Vellaveto policies.
   *
   * Designed to be used as the `toolPermissionCallback` parameter of the
   * Claude Agent SDK. Returns true to allow, false to deny.
   *
   * @param toolName - Name of the tool being called.
   * @param args - Tool call arguments.
   * @param agentName - Optional agent name for context.
   * @returns True if allowed, false if denied.
   * @throws ApprovalRequired if the action requires human approval.
   */
  async check(
    toolName: string,
    args: Record<string, unknown>,
    agentName?: string
  ): Promise<boolean> {
    try {
      const { paths, domains } = this.extractTargets(args);
      const ctx = this.buildContext(agentName);

      const result = await this.client.evaluate(
        {
          tool: toolName,
          function: "*",
          parameters: args,
          target_paths: paths,
          target_domains: domains,
        },
        ctx
      );

      this.appendChain(toolName);

      if (result.verdict === Verdict.Allow) {
        return true;
      } else if (result.verdict === Verdict.RequireApproval) {
        throw new ApprovalRequired(
          result.reason ?? "Approval required",
          result.approval_id ?? ""
        );
      } else {
        return false;
      }
    } catch (e) {
      if (e instanceof PolicyDenied || e instanceof ApprovalRequired) {
        throw e;
      }
      if (this.denyOnError) {
        return false;
      }
      return true;
    }
  }

  /**
   * Filter available tools to only those allowed by current policies.
   *
   * Useful for populating the Claude Agent SDK's `allowedTools`
   * configuration based on the current policy state.
   *
   * @param availableTools - List of tool names to filter.
   * @param agentName - Optional agent name for context.
   * @returns Filtered list of allowed tool names.
   */
  async filterAllowedTools(
    availableTools: string[],
    agentName?: string
  ): Promise<string[]> {
    const allowed: string[] = [];
    for (const toolName of availableTools) {
      try {
        if (await this.check(toolName, {}, agentName)) {
          allowed.push(toolName);
        }
      } catch {
        // Skip tools that throw (denied or require approval)
        continue;
      }
    }
    return allowed;
  }

  /**
   * Create a wrapped tool function with policy enforcement.
   *
   * @param fn - The tool function to wrap.
   * @param toolName - Override tool name (defaults to function name).
   * @param agentName - Optional agent name for context.
   * @returns Wrapped function with policy enforcement.
   */
  wrapTool<T extends (...args: unknown[]) => unknown>(
    fn: T,
    toolName?: string,
    agentName?: string
  ): (...args: Parameters<T>) => Promise<ReturnType<T>> {
    const name = toolName ?? fn.name;

    const wrapper = async (...args: Parameters<T>): Promise<ReturnType<T>> => {
      const kwargs =
        args.length === 1 && typeof args[0] === "object" && args[0] !== null
          ? (args[0] as Record<string, unknown>)
          : {};

      const allowed = await this.check(name, kwargs, agentName);
      if (!allowed) {
        throw new PolicyDenied(`Tool '${name}' denied by Vellaveto policy`);
      }
      return fn(...args) as ReturnType<T>;
    };

    Object.defineProperty(wrapper, "name", { value: fn.name });
    return wrapper;
  }
}
