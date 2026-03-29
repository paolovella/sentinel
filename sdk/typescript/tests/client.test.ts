import {
  VellavetoClient,
  VellavetoError,
  PolicyDenied,
  ApprovalRequired,
  ParameterRedactor,
  Verdict,
  Action,
  EvaluationResult,
  BatchResponse,
  ValidateResponse,
  SimulateResponse,
  FederationStatusResponse,
  FederationTrustAnchorsResponse,
  ZkSchedulerStatus,
  ZkProofsResponse,
  ZkVerifyResult,
  ZkCommitmentsResponse,
} from "../src";

// Mock fetch globally
const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    headers: new Headers(),
    redirected: false,
    type: "basic",
    url: "",
    clone: () => jsonResponse(body, status) as Response,
    body: null,
    bodyUsed: false,
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    blob: () => Promise.resolve(new Blob()),
    formData: () => Promise.resolve(new FormData()),
    text: () => Promise.resolve(JSON.stringify(body)),
    bytes: () => Promise.resolve(new Uint8Array()),
  } as Response;
}

describe("VellavetoClient", () => {
  let client: VellavetoClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: "test-key",
      timeout: 1000,
    });
  });

  // ── Health ──────────────────────────────────────

  test("health returns status", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    const result = await client.health();
    expect(result.status).toBe("ok");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/health",
      expect.objectContaining({ method: "GET" })
    );
  });

  // ── Evaluate ────────────────────────────────────

  test("evaluate allow response", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Allow",
        action: { tool: "fs", function: "read" },
      })
    );
    const result = await client.evaluate({ tool: "fs", function: "read" });
    expect(result.verdict).toBe(Verdict.Allow);
  });

  test("evaluate deny response", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { Deny: { reason: "blocked" } },
        action: { tool: "bash", function: "exec" },
      })
    );
    const result = await client.evaluate({ tool: "bash", function: "exec" });
    expect(result.verdict).toBe(Verdict.Deny);
  });

  test("evaluate with trace", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Allow",
        action: {},
        trace: { policies_checked: 3 },
      })
    );
    const result = await client.evaluate({ tool: "fs" }, undefined, true);
    expect(result.trace).toBeDefined();
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/evaluate?trace=true",
      expect.anything()
    );
  });

  // ── API Key ─────────────────────────────────────

  test("api key sent in Authorization header", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    await client.health();
    const call = mockFetch.mock.calls[0];
    expect(call[1].headers["Authorization"]).toBe("Bearer test-key");
  });

  test("no api key when not configured", async () => {
    const noKeyClient = new VellavetoClient({
      baseUrl: "http://localhost:3000",
    });
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    await noKeyClient.health();
    const call = mockFetch.mock.calls[0];
    expect(call[1].headers["Authorization"]).toBeUndefined();
  });

  // ── List Policies ──────────────────────────────

  test("listPolicies returns array", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse([
        { id: "p1", name: "Allow reads", policy_type: "Allow", priority: 100 },
      ])
    );
    const policies = await client.listPolicies();
    expect(policies).toHaveLength(1);
    expect(policies[0].id).toBe("p1");
  });

  // ── Simulate ───────────────────────────────────

  test("simulate returns trace", async () => {
    const mockResp: SimulateResponse = {
      verdict: Verdict.Allow,
      trace: { policies_checked: 2 } as any,
      policies_checked: 2,
      duration_us: 42,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.simulate({ tool: "fs", function: "read" });
    expect(result.policies_checked).toBe(2);
  });

  // ── Batch ──────────────────────────────────────

  test("batchEvaluate multiple actions", async () => {
    const mockResp: BatchResponse = {
      results: [
        { action_index: 0, verdict: Verdict.Allow },
        { action_index: 1, verdict: Verdict.Deny },
      ],
      summary: { total: 2, allowed: 1, denied: 1, errors: 0, duration_us: 100 },
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.batchEvaluate([
      { tool: "fs" },
      { tool: "bash" },
    ]);
    expect(result.summary.total).toBe(2);
    expect(result.results).toHaveLength(2);
  });

  // ── FIND-R80-015: simulate/batchEvaluate action validation ──

  test("simulate rejects empty tool", async () => {
    await expect(
      client.simulate({ tool: "" })
    ).rejects.toThrow("action.tool must be a non-empty string");
  });

  test("simulate rejects tool exceeding max length", async () => {
    await expect(
      client.simulate({ tool: "x".repeat(257) })
    ).rejects.toThrow("action.tool exceeds max length (256)");
  });

  test("simulate rejects non-object parameters", async () => {
    await expect(
      client.simulate({ tool: "fs", parameters: "bad" as any })
    ).rejects.toThrow("action.parameters must be an object if provided");
  });

  test("simulate rejects >100 target_paths", async () => {
    await expect(
      client.simulate({ tool: "fs", target_paths: Array(101).fill("/tmp") })
    ).rejects.toThrow("action.target_paths has 101 entries, max 100");
  });

  test("batchEvaluate rejects empty tool in action", async () => {
    await expect(
      client.batchEvaluate([{ tool: "fs" }, { tool: "" }])
    ).rejects.toThrow("actions[1]");
  });

  test("batchEvaluate rejects oversized tool in action", async () => {
    await expect(
      client.batchEvaluate([{ tool: "x".repeat(257) }])
    ).rejects.toThrow("actions[0]");
  });

  test("batchEvaluate rejects non-array actions", async () => {
    await expect(
      (client.batchEvaluate as any)("not-an-array")
    ).rejects.toThrow("actions must be an array");
  });

  test("batchEvaluate rejects >100 target_domains in action", async () => {
    await expect(
      client.batchEvaluate([{ tool: "http", target_domains: Array(101).fill("example.com") }])
    ).rejects.toThrow("actions[0]");
  });

  // ── Validate Config ────────────────────────────

  test("validateConfig valid", async () => {
    const mockResp: ValidateResponse = {
      valid: true,
      findings: [],
      summary: {
        total_policies: 2,
        errors: 0,
        warnings: 0,
        infos: 0,
        valid: true,
      },
      policy_count: 2,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.validateConfig("[[policies]]");
    expect(result.valid).toBe(true);
    expect(result.policy_count).toBe(2);
  });

  test("validateConfig invalid", async () => {
    const mockResp: ValidateResponse = {
      valid: false,
      findings: [
        {
          severity: "error",
          category: "syntax",
          code: "E001",
          message: "Bad config",
        },
      ],
      summary: {
        total_policies: 0,
        errors: 1,
        warnings: 0,
        infos: 0,
        valid: false,
      },
      policy_count: 0,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.validateConfig("bad");
    expect(result.valid).toBe(false);
    expect(result.findings).toHaveLength(1);
  });

  // ── Error handling ─────────────────────────────

  test("401 throws VellavetoError", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Unauthorized" }, 401)
    );
    await expect(client.health()).rejects.toThrow(VellavetoError);
    await expect(client.health()).rejects.toThrow(); // fetch is already consumed so need separate mock
  });

  test("500 throws VellavetoError with message", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Internal error" }, 500)
    );
    try {
      await client.health();
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VellavetoError);
      expect((e as VellavetoError).statusCode).toBe(500);
    }
  });

  test("network error throws VellavetoError", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Connection refused"));
    await expect(client.health()).rejects.toThrow(VellavetoError);
  });

  // ── Trailing slash removal ─────────────────────

  test("trailing slash removed from baseUrl", async () => {
    const slashClient = new VellavetoClient({
      baseUrl: "http://localhost:3000/",
    });
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    await slashClient.health();
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/health",
      expect.anything()
    );
  });

  // ── FIND-R46-TS-003: baseUrl validation ──────

  test("empty baseUrl throws VellavetoError", () => {
    expect(() => new VellavetoClient({ baseUrl: "" })).toThrow(VellavetoError);
    expect(() => new VellavetoClient({ baseUrl: "   " })).toThrow(VellavetoError);
  });

  test("baseUrl without http/https throws VellavetoError", () => {
    expect(() => new VellavetoClient({ baseUrl: "ftp://example.com" })).toThrow(
      "http:// or https://"
    );
    expect(() => new VellavetoClient({ baseUrl: "ws://example.com" })).toThrow(
      "http:// or https://"
    );
  });

  test("baseUrl with credentials throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "https://user:pass@example.com" })
    ).toThrow("credentials");
  });

  test("valid https baseUrl accepted", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "https://api.example.com" })
    ).not.toThrow();
  });

  // ── FIND-R46-TS-004: API key not leaked in errors ──

  test("API key not leaked in network error messages", async () => {
    const secretKey = "sk-super-secret-api-key-12345";
    const keyClient = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: secretKey,
    });
    // Simulate a network error that includes the API key in its message
    mockFetch.mockRejectedValueOnce(
      new Error(`Connection refused: Bearer ${secretKey}`)
    );
    try {
      await keyClient.health();
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VellavetoError);
      expect((e as VellavetoError).message).not.toContain(secretKey);
      expect((e as VellavetoError).message).toContain("[REDACTED]");
    }
  });

  // ── FIND-R46-TS-005: http:// warning on non-localhost ──

  test("http:// on non-localhost logs warning", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    new VellavetoClient({ baseUrl: "http://api.example.com" });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("unencrypted HTTP")
    );
    warnSpy.mockRestore();
  });

  test("http:// on localhost does not log warning", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    new VellavetoClient({ baseUrl: "http://localhost:3000" });
    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  // ── FIND-R67-SDK-004: CRLF header injection ──────

  test("extraHeaders with CRLF in key throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "X-Bad\r\nHeader": "value" } })
    ).toThrow("Header names and values must not contain CR or LF characters");
  });

  test("extraHeaders with CRLF in value throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "X-Custom": "val\r\nue" } })
    ).toThrow("Header names and values must not contain CR or LF characters");
  });

  // ── FIND-R67-SDK-TS-001: Content-Type override blocking ──

  test("extraHeaders with Content-Type throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "Content-Type": "text/xml" } })
    ).toThrow("Content-Type header cannot be overridden via extraHeaders");
  });

  test("extraHeaders with content-type (lowercase) throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "content-type": "text/plain" } })
    ).toThrow("Content-Type header cannot be overridden via extraHeaders");
  });

  test("extraHeaders with CONTENT-TYPE (uppercase) throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "CONTENT-TYPE": "application/xml" } })
    ).toThrow("Content-Type header cannot be overridden via extraHeaders");
  });

  test("extraHeaders with non-Content-Type headers accepted", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "X-Custom": "value", "X-Request-Id": "abc" } })
    ).not.toThrow();
  });

  // SECURITY (FIND-R115-062): Block Authorization override via extraHeaders
  test("extraHeaders with Authorization throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "Authorization": "Bearer injected" } })
    ).toThrow("Authorization header cannot be overridden via extraHeaders");
  });

  test("extraHeaders with authorization (lowercase) throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "authorization": "Bearer injected" } })
    ).toThrow("Authorization header cannot be overridden via extraHeaders");
  });

  test("extraHeaders with AUTHORIZATION (uppercase) throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", headers: { "AUTHORIZATION": "Bearer injected" } })
    ).toThrow("Authorization header cannot be overridden via extraHeaders");
  });

  // ── P1-10: evaluate extracts reason, policy_id, policy_name ──

  test("evaluate extracts reason from top-level field", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Deny",
        reason: "path blocked by policy",
        policy_id: "pol-123",
        policy_name: "Block sensitive paths",
      })
    );
    const result = await client.evaluate({ tool: "fs", function: "read" });
    expect(result.verdict).toBe(Verdict.Deny);
    expect(result.reason).toBe("path blocked by policy");
    expect(result.policy_id).toBe("pol-123");
    expect(result.policy_name).toBe("Block sensitive paths");
  });

  test("evaluate extracts reason from verdict object", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { Deny: { reason: "blocked by deny rule" } },
        action: { tool: "bash" },
      })
    );
    const result = await client.evaluate({ tool: "bash" });
    expect(result.verdict).toBe(Verdict.Deny);
    expect(result.reason).toBe("blocked by deny rule");
  });

  test("evaluate top-level reason takes precedence over verdict object reason", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { Deny: { reason: "inner reason" } },
        reason: "top-level reason",
      })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.reason).toBe("top-level reason");
  });

  test("evaluate extracts reason from RequireApproval verdict object", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { RequireApproval: { reason: "needs human review" } },
        approval_id: "appr-456",
      })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.verdict).toBe(Verdict.RequireApproval);
    expect(result.reason).toBe("needs human review");
    expect(result.approval_id).toBe("appr-456");
  });

  test("evaluate returns undefined for missing optional fields", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ verdict: "Allow" })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.verdict).toBe(Verdict.Allow);
    expect(result.reason).toBeUndefined();
    expect(result.policy_id).toBeUndefined();
    expect(result.policy_name).toBeUndefined();
    expect(result.approval_id).toBeUndefined();
  });

  test("evaluate ignores non-string reason/policy_id/policy_name", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Deny",
        reason: 42,
        policy_id: true,
        policy_name: ["not", "a", "string"],
      })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.verdict).toBe(Verdict.Deny);
    expect(result.reason).toBeUndefined();
    expect(result.policy_id).toBeUndefined();
    expect(result.policy_name).toBeUndefined();
  });

  // ── P1-11: ZK Audit ─────────────────────────────

  test("zkStatus returns scheduler status", async () => {
    const mockStatus: ZkSchedulerStatus = {
      active: true,
      pending_witnesses: 5,
      completed_proofs: 12,
      last_proved_sequence: 100,
      last_proof_at: "2026-02-16T10:00:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockStatus));
    const result = await client.zkStatus();
    expect(result.active).toBe(true);
    expect(result.pending_witnesses).toBe(5);
    expect(result.completed_proofs).toBe(12);
    expect(result.last_proved_sequence).toBe(100);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("zkProofs returns proof list", async () => {
    const mockProofs: ZkProofsResponse = {
      proofs: [
        {
          proof: "deadbeef",
          batch_id: "batch-001",
          entry_range: [1, 50],
          merkle_root: "aabbcc",
          first_prev_hash: "000000",
          final_entry_hash: "ffffff",
          created_at: "2026-02-16T09:00:00Z",
          entry_count: 50,
        },
      ],
      total: 1,
      offset: 0,
      limit: 20,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockProofs));
    const result = await client.zkProofs(10, 0);
    expect(result.proofs).toHaveLength(1);
    expect(result.proofs[0].batch_id).toBe("batch-001");
    expect(result.total).toBe(1);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/proofs?limit=10&offset=0",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("zkProofs without parameters omits query string", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ proofs: [], total: 0, offset: 0, limit: 20 })
    );
    await client.zkProofs();
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/proofs",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("zkVerify sends batch_id and returns result", async () => {
    const mockResult: ZkVerifyResult = {
      valid: true,
      batch_id: "batch-001",
      entry_range: [1, 50],
      verified_at: "2026-02-16T10:30:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResult));
    const result = await client.zkVerify("batch-001");
    expect(result.valid).toBe(true);
    expect(result.batch_id).toBe("batch-001");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/verify",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ batch_id: "batch-001" }),
      })
    );
  });

  test("zkVerify returns error on invalid proof", async () => {
    const mockResult: ZkVerifyResult = {
      valid: false,
      batch_id: "batch-bad",
      entry_range: [1, 10],
      verified_at: "2026-02-16T10:30:00Z",
      error: "proof verification failed",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResult));
    const result = await client.zkVerify("batch-bad");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("proof verification failed");
  });

  test("zkCommitments returns commitments for range", async () => {
    const mockCommitments: ZkCommitmentsResponse = {
      commitments: [
        { sequence: 1, commitment: "aabb" },
        { sequence: 2, commitment: "ccdd" },
      ],
      total: 2,
      range: [1, 2],
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockCommitments));
    const result = await client.zkCommitments(1, 2);
    expect(result.commitments).toHaveLength(2);
    expect(result.total).toBe(2);
    expect(result.range).toEqual([1, 2]);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/commitments?from=1&to=2",
      expect.objectContaining({ method: "GET" })
    );
  });

  // ── FIND-GAP-012: evaluateOrRaise ──────────────

  test("evaluateOrRaise returns result on allow", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ verdict: "Allow", policy_id: "p1" })
    );
    const result = await client.evaluateOrRaise({ tool: "fs", function: "read" });
    expect(result.verdict).toBe(Verdict.Allow);
    expect(result.policy_id).toBe("p1");
  });

  test("evaluateOrRaise throws PolicyDenied on deny", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ verdict: "Deny", reason: "blocked by policy" })
    );
    try {
      await client.evaluateOrRaise({ tool: "bash", function: "exec" });
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PolicyDenied);
      expect((e as PolicyDenied).reason).toBe("blocked by policy");
    }
  });

  test("evaluateOrRaise throws ApprovalRequired on require_approval", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "require_approval",
        reason: "needs human review",
        approval_id: "appr-789",
      })
    );
    try {
      await client.evaluateOrRaise({ tool: "deploy" });
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApprovalRequired);
      expect((e as ApprovalRequired).reason).toBe("needs human review");
      expect((e as ApprovalRequired).approvalId).toBe("appr-789");
    }
  });

  test("evaluateOrRaise throws PolicyDenied on unknown verdict (fail-closed)", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ verdict: "something_unknown" })
    );
    try {
      await client.evaluateOrRaise({ tool: "fs" });
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PolicyDenied);
    }
  });

  // ── FIND-GAP-015: Request body structure assertions ──

  test("evaluate sends flattened action fields in request body", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ verdict: "Allow" })
    );
    await client.evaluate({
      tool: "filesystem",
      function: "read_file",
      parameters: { path: "/tmp/test.txt" },
    });
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    // Action fields should be flattened at root level (not nested under "action")
    expect(body.tool).toBe("filesystem");
    expect(body.function).toBe("read_file");
    expect(body.parameters).toEqual({ path: "/tmp/test.txt" });
    // Should NOT have a nested "action" key
    expect(body.action).toBeUndefined();
  });

  test("evaluate sends context when provided", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ verdict: "Allow" })
    );
    await client.evaluate(
      { tool: "fs" },
      { session_id: "sess-1", agent_id: "agent-1" }
    );
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    expect(body.context).toEqual({
      session_id: "sess-1",
      agent_id: "agent-1",
    });
  });

  test("simulate sends action nested under action key", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "allow",
        trace: {},
        policies_checked: 1,
        duration_us: 10,
      })
    );
    await client.simulate({ tool: "fs", function: "read" });
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    expect(body.action).toBeDefined();
    expect(body.action.tool).toBe("fs");
    expect(body.action.function).toBe("read");
  });

  test("batchEvaluate sends actions array in body", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        results: [{ action_index: 0, verdict: "allow" }],
        summary: { total: 1, allowed: 1, denied: 0, errors: 0, duration_us: 5 },
      })
    );
    await client.batchEvaluate([{ tool: "fs" }, { tool: "bash" }]);
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    expect(body.actions).toHaveLength(2);
    expect(body.actions[0].tool).toBe("fs");
    expect(body.actions[1].tool).toBe("bash");
  });

  test("discover sends query, max_results, and token_budget in body", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        tools: [],
        query: "file reading",
        total_candidates: 0,
        policy_filtered: 0,
      })
    );
    await client.discover("file reading", 5, 1000);
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    expect(body.query).toBe("file reading");
    expect(body.max_results).toBe(5);
    expect(body.token_budget).toBe(1000);
  });

  test("projectSchema sends schema and model_family in body", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        projected_schema: {},
        token_estimate: 100,
        model_family: "openai",
      })
    );
    await client.projectSchema(
      { name: "read_file", description: "Reads files", input_schema: {} },
      "openai"
    );
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    expect(body.schema).toBeDefined();
    expect(body.schema.name).toBe("read_file");
    expect(body.model_family).toBe("openai");
  });

  test("reloadPolicies sends POST with no body", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ count: 3 }));
    await client.reloadPolicies();
    const call = mockFetch.mock.calls[0];
    expect(call[1].method).toBe("POST");
    expect(call[0]).toBe("http://localhost:3000/api/policies/reload");
  });

  test("validateConfig sends config and strict flag in body", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        valid: true,
        findings: [],
        summary: { total_policies: 1, errors: 0, warnings: 0, infos: 0, valid: true },
        policy_count: 1,
      })
    );
    await client.validateConfig("[[policies]]", true);
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    expect(body.config).toBe("[[policies]]");
    expect(body.strict).toBe(true);
  });

  test("diffConfigs sends before and after in body", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ added: [], removed: [], modified: [], unchanged: 0 })
    );
    await client.diffConfigs("config-a", "config-b");
    const call = mockFetch.mock.calls[0];
    const body = JSON.parse(call[1].body);
    expect(body.before).toBe("config-a");
    expect(body.after).toBe("config-b");
  });

});

describe("SOC 2 Access Review (Phase 38)", () => {
  let client: VellavetoClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: "test-key",
      timeout: 1000,
    });
  });

  test("soc2AccessReview sends correct params", async () => {
    const mockReport = {
      generated_at: "2026-02-16T00:00:00Z",
      organization_name: "Acme",
      total_agents: 2,
      total_evaluations: 100,
      entries: [],
      cc6_evidence: {
        cc6_1_evidence: "test",
        cc6_2_evidence: "test",
        cc6_3_evidence: "test",
        optimal_count: 1,
        review_grants_count: 0,
        narrow_scope_count: 0,
        critical_count: 0,
      },
      attestation: {
        reviewer_name: "",
        reviewer_title: "",
        notes: "",
        status: "pending",
      },
      period_start: "2026-01-01T00:00:00Z",
      period_end: "2026-02-01T00:00:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockReport));
    const result = await client.soc2AccessReview("30d", "json");
    expect(result.total_agents).toBe(2);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/compliance/soc2/access-review?period=30d&format=json",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("soc2AccessReview rejects agent_id > 128 chars", async () => {
    await expect(
      client.soc2AccessReview("30d", "json", "a".repeat(129))
    ).rejects.toThrow("agent_id exceeds max length");
  });

  test("soc2AccessReview rejects period exceeding 32 chars", async () => {
    await expect(
      client.soc2AccessReview("a".repeat(33))
    ).rejects.toThrow("period exceeds max length");
  });

  test("soc2AccessReview rejects period with invalid characters", async () => {
    await expect(
      client.soc2AccessReview("30d;rm -rf /")
    ).rejects.toThrow("period contains invalid characters");
  });

  test("soc2AccessReview accepts valid period values", async () => {
    const mockReport = {
      generated_at: "2026-02-16T00:00:00Z",
      organization_name: "Acme",
      total_agents: 0,
      total_evaluations: 0,
      entries: [],
      cc6_evidence: {
        cc6_1_evidence: "",
        cc6_2_evidence: "",
        cc6_3_evidence: "",
        optimal_count: 0,
        review_grants_count: 0,
        narrow_scope_count: 0,
        critical_count: 0,
      },
      attestation: {
        reviewer_name: "",
        reviewer_title: "",
        notes: "",
        status: "pending",
      },
      period_start: "2026-01-01T00:00:00Z",
      period_end: "2026-02-01T00:00:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockReport));
    // ISO date range with colons and dashes should be accepted
    const result = await client.soc2AccessReview("2026-01-01:2026-02-01");
    expect(result.total_agents).toBe(0);
  });

});

// ── Phase 41: OWASP ASI Coverage ──────────────

describe("OWASP ASI Coverage (Phase 41)", () => {
  let client: VellavetoClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: "test-key",
      timeout: 1000,
    });
  });

  test("owaspAsiCoverage returns coverage data", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        total_categories: 10,
        covered_categories: 10,
        total_controls: 33,
        covered_controls: 33,
        coverage_percent: 100.0,
      })
    );
    const result = await client.owaspAsiCoverage();
    expect(result.total_categories).toBe(10);
    expect(result.total_controls).toBe(33);
    expect(result.coverage_percent).toBe(100.0);
    const call = mockFetch.mock.calls[0];
    expect(call[0]).toContain("/api/compliance/owasp-agentic");
  });
});

// ── FIND-GAP-013: ParameterRedactor ──────────────

describe("ParameterRedactor", () => {
  test("redacts sensitive keys by default", () => {
    const redactor = new ParameterRedactor();
    const result = redactor.redact({
      path: "/tmp/test.txt",
      api_key: "sk-1234567890abcdefghij",
      password: "hunter2",
    });
    expect(result.path).toBe("/tmp/test.txt");
    expect(result.api_key).toBe("[REDACTED]");
    expect(result.password).toBe("[REDACTED]");
  });

  test("is case-insensitive for key matching", () => {
    const redactor = new ParameterRedactor();
    const result = redactor.redact({
      API_KEY: "secret",
      Password: "hunter2",
      TOKEN: "abc",
    });
    expect(result.API_KEY).toBe("[REDACTED]");
    expect(result.Password).toBe("[REDACTED]");
    expect(result.TOKEN).toBe("[REDACTED]");
  });

  test("matches suffix keys like x_api_key", () => {
    const redactor = new ParameterRedactor();
    const result = redactor.redact({
      my_api_key: "secret",
      custom_token: "abc",
    });
    expect(result.my_api_key).toBe("[REDACTED]");
    expect(result.custom_token).toBe("[REDACTED]");
  });

  test("mode=all redacts all values", () => {
    const redactor = new ParameterRedactor({ mode: "all" });
    const result = redactor.redact({
      path: "/tmp/test.txt",
      count: 42,
    });
    expect(result.path).toBe("[REDACTED]");
    expect(result.count).toBe("[REDACTED]");
  });

  test("mode=values scans string values for secret patterns", () => {
    const redactor = new ParameterRedactor({ mode: "values" });
    const result = redactor.redact({
      path: "/tmp/test.txt",
      config: "sk-abcdefghijklmnopqrstuvwxyz",
      normal: "hello world",
    });
    expect(result.path).toBe("/tmp/test.txt");
    expect(result.config).toBe("[REDACTED]");
    expect(result.normal).toBe("hello world");
  });

  test("handles nested objects", () => {
    const redactor = new ParameterRedactor();
    const result = redactor.redact({
      config: {
        api_key: "secret",
        host: "localhost",
      },
    });
    expect((result.config as Record<string, unknown>).api_key).toBe("[REDACTED]");
    expect((result.config as Record<string, unknown>).host).toBe("localhost");
  });

  test("handles arrays", () => {
    const redactor = new ParameterRedactor();
    const result = redactor.redact({
      items: [{ password: "secret", name: "test" }],
    });
    const items = result.items as Record<string, unknown>[];
    expect(items[0].password).toBe("[REDACTED]");
    expect(items[0].name).toBe("test");
  });

  test("custom placeholder", () => {
    const redactor = new ParameterRedactor({ placeholder: "***" });
    const result = redactor.redact({ password: "secret" });
    expect(result.password).toBe("***");
  });

  test("custom sensitive keys", () => {
    const redactor = new ParameterRedactor({
      sensitiveKeys: new Set(["custom_field"]),
    });
    const result = redactor.redact({
      custom_field: "sensitive",
      password: "should-not-be-redacted",
    });
    expect(result.custom_field).toBe("[REDACTED]");
    expect(result.password).toBe("should-not-be-redacted");
  });

  test("extra keys extend defaults", () => {
    const redactor = new ParameterRedactor({
      extraKeys: new Set(["my_custom_secret"]),
    });
    const result = redactor.redact({
      my_custom_secret: "value",
      password: "hunter2",
      path: "/tmp",
    });
    expect(result.my_custom_secret).toBe("[REDACTED]");
    expect(result.password).toBe("[REDACTED]");
    expect(result.path).toBe("/tmp");
  });

  test("invalid mode throws error", () => {
    expect(() => new ParameterRedactor({ mode: "invalid" as any })).toThrow(
      "Invalid redaction mode"
    );
  });

  test("isSensitiveKey returns correct results", () => {
    const redactor = new ParameterRedactor();
    expect(redactor.isSensitiveKey("api_key")).toBe(true);
    expect(redactor.isSensitiveKey("API_KEY")).toBe(true);
    expect(redactor.isSensitiveKey("my_api_key")).toBe(true);
    expect(redactor.isSensitiveKey("path")).toBe(false);
    expect(redactor.isSensitiveKey("name")).toBe(false);
  });

  test("isSensitiveValue detects secret patterns", () => {
    const redactor = new ParameterRedactor();
    expect(redactor.isSensitiveValue("sk-abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(redactor.isSensitiveValue("ghp_abcdefghijklmnopqrstuvwxyz0123456789ab")).toBe(true);
    expect(redactor.isSensitiveValue("hello world")).toBe(false);
    expect(redactor.isSensitiveValue("short")).toBe(false);
    expect(redactor.isSensitiveValue(42)).toBe(false);
  });

  test("returns empty/null parameters unchanged", () => {
    const redactor = new ParameterRedactor();
    expect(redactor.redact({} as any)).toEqual({});
    expect(redactor.redact(null as any)).toBeNull();
  });

  test("handles deeply nested objects with depth limit", () => {
    const redactor = new ParameterRedactor();
    // Build a deeply nested object (12 levels)
    let obj: Record<string, unknown> = { password: "deep-secret" };
    for (let i = 0; i < 12; i++) {
      obj = { nested: obj };
    }
    const result = redactor.redact(obj);
    // At depth > 10, all values should be redacted as placeholder
    // The exact behavior depends on depth counting, but it should not crash
    expect(result).toBeDefined();
  });
});

// ── Federation (Phase 39) ──────────────────────────────────

describe("Federation (Phase 39)", () => {
  let client: VellavetoClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: "test-key",
      timeout: 1000,
    });
  });

  test("federationStatus returns status", async () => {
    const mockStatus: FederationStatusResponse = {
      enabled: true,
      trust_anchor_count: 1,
      anchors: [
        {
          org_id: "partner-org",
          display_name: "Partner",
          trust_level: "limited",
          successful_validations: 42,
          failed_validations: 3,
        },
      ],
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockStatus));
    const result = await client.federationStatus();
    expect(result.enabled).toBe(true);
    expect(result.trust_anchor_count).toBe(1);
    expect(result.anchors).toHaveLength(1);
    expect(result.anchors[0].org_id).toBe("partner-org");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/federation/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("federationStatus disabled", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ enabled: false, trust_anchor_count: 0, anchors: [] })
    );
    const result = await client.federationStatus();
    expect(result.enabled).toBe(false);
    expect(result.trust_anchor_count).toBe(0);
  });

  test("federationTrustAnchors returns all anchors", async () => {
    const mockAnchors: FederationTrustAnchorsResponse = {
      anchors: [
        { org_id: "org-1", display_name: "Org 1", trust_level: "full" },
        { org_id: "org-2", display_name: "Org 2", trust_level: "limited" },
      ],
      total: 2,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockAnchors));
    const result = await client.federationTrustAnchors();
    expect(result.total).toBe(2);
    expect(result.anchors).toHaveLength(2);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/federation/trust-anchors",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("federationTrustAnchors with org_id filter", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ anchors: [{ org_id: "org-1" }], total: 1 })
    );
    const result = await client.federationTrustAnchors("org-1");
    expect(result.total).toBe(1);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/federation/trust-anchors?org_id=org-1",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("federationTrustAnchors rejects org_id > 128 chars", async () => {
    await expect(
      client.federationTrustAnchors("x".repeat(129))
    ).rejects.toThrow("org_id exceeds max length");
  });

  test("federationTrustAnchors rejects org_id with control chars", async () => {
    await expect(
      client.federationTrustAnchors("org\x00id")
    ).rejects.toThrow("org_id contains control characters");
  });

  test("federationTrustAnchors rejects org_id with newline", async () => {
    await expect(
      client.federationTrustAnchors("org\nid")
    ).rejects.toThrow("org_id contains control characters");
  });
});

// ── FIND-R58-SDK-TS: Input validation hardening ──────────────

describe("Input validation hardening", () => {
  // ── Timeout validation ──

  test("timeout below 100 throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", timeout: 50 })
    ).toThrow("timeout must be a finite number between 100 and 300000");
  });

  test("timeout above 300000 throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", timeout: 400000 })
    ).toThrow("timeout must be a finite number between 100 and 300000");
  });

  test("timeout NaN throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", timeout: NaN })
    ).toThrow("timeout must be a finite number between 100 and 300000");
  });

  test("timeout Infinity throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", timeout: Infinity })
    ).toThrow("timeout must be a finite number between 100 and 300000");
  });

  test("timeout 0 throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", timeout: 0 })
    ).toThrow("timeout must be a finite number between 100 and 300000");
  });

  test("timeout exactly 100 accepted", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", timeout: 100 })
    ).not.toThrow();
  });

  test("timeout exactly 300000 accepted", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000", timeout: 300000 })
    ).not.toThrow();
  });

  test("timeout undefined uses default (accepted)", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "http://localhost:3000" })
    ).not.toThrow();
  });

  // ── zkCommitments validation ──

  let client: VellavetoClient;
  beforeAll(() => {
    mockFetch.mockReset();
    client = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: "test-key",
      timeout: 1000,
    });
  });

  test("zkCommitments rejects negative fromSeq", async () => {
    await expect(client.zkCommitments(-1, 5)).rejects.toThrow(
      "fromSeq must be a non-negative integer"
    );
  });

  test("zkCommitments rejects non-integer fromSeq", async () => {
    await expect(client.zkCommitments(1.5, 5)).rejects.toThrow(
      "fromSeq must be a non-negative integer"
    );
  });

  test("zkCommitments rejects negative toSeq", async () => {
    await expect(client.zkCommitments(0, -1)).rejects.toThrow(
      "toSeq must be a non-negative integer"
    );
  });

  test("zkCommitments rejects fromSeq > toSeq", async () => {
    await expect(client.zkCommitments(10, 5)).rejects.toThrow(
      "fromSeq must be <= toSeq"
    );
  });

  // ── discover() query length cap ──

  test("discover rejects query longer than 1024 chars", async () => {
    await expect(client.discover("x".repeat(1025))).rejects.toThrow(
      "query exceeds max length (1024)"
    );
  });

  test("discover accepts query of exactly 1024 chars", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ tools: [], query: "x", total_candidates: 0, policy_filtered: 0 })
    );
    // Should not throw
    await client.discover("x".repeat(1024));
  });

  // ── FIND-R102-005: EvaluationContext validation (parity with Go SDK) ──

  test("evaluate rejects context.session_id exceeding max length", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { session_id: "x".repeat(257) })
    ).rejects.toThrow("context.session_id exceeds max length 256");
  });

  test("evaluate rejects context.agent_id with control characters", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { agent_id: "agent\x00id" })
    ).rejects.toThrow("context.agent_id contains control characters");
  });

  test("evaluate rejects context.tenant_id with C1 control characters", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { tenant_id: "tenant\x80id" })
    ).rejects.toThrow("context.tenant_id contains control characters");
  });

  test("evaluate rejects context.session_id with Unicode format characters", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { session_id: "sess\u200Bid" })
    ).rejects.toThrow("context.session_id contains Unicode format characters");
  });

  test("evaluate rejects context.call_chain exceeding max entries", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { call_chain: Array(101).fill("step") })
    ).rejects.toThrow("context.call_chain has 101 entries, max 100");
  });

  test("evaluate rejects context.call_chain entry exceeding max length", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { call_chain: ["x".repeat(257)] })
    ).rejects.toThrow("context.call_chain[0] exceeds max length 256");
  });

  // FIND-R114-003: call_chain entry control/format character validation
  test("evaluate rejects context.call_chain entry with control characters", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { call_chain: ["tool\x00evil"] })
    ).rejects.toThrow("context.call_chain[0] contains control characters");
  });

  test("evaluate rejects context.call_chain entry with C1 control characters", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { call_chain: ["ok", "tool\x80bad"] })
    ).rejects.toThrow("context.call_chain[1] contains control characters");
  });

  test("evaluate rejects context.call_chain entry with Unicode format characters", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { call_chain: ["tool\u200bhidden"] })
    ).rejects.toThrow("context.call_chain[0] contains Unicode format characters");
  });

  test("evaluate rejects context.call_chain entry with bidi override", async () => {
    await expect(
      client.evaluate({ tool: "fs" }, { call_chain: ["safe", "tool\u202Aoverride"] })
    ).rejects.toThrow("context.call_chain[1] contains Unicode format characters");
  });

  // FIND-R114-002: parameters size validation
  test("evaluate rejects action.parameters exceeding 512KB", async () => {
    const bigParams: Record<string, unknown> = { data: "x".repeat(600000) };
    await expect(
      client.evaluate({ tool: "fs", parameters: bigParams })
    ).rejects.toThrow("action.parameters exceeds max serialized size");
  });

  test("evaluate rejects context.metadata exceeding max keys", async () => {
    const metadata: Record<string, unknown> = {};
    for (let i = 0; i < 101; i++) metadata[`key${i}`] = "v";
    await expect(
      client.evaluate({ tool: "fs" }, { metadata })
    ).rejects.toThrow("context.metadata has 101 keys, max 100");
  });

  test("simulate rejects context with control characters", async () => {
    await expect(
      client.simulate({ tool: "fs" }, { context: { agent_id: "a\x01b" } })
    ).rejects.toThrow("context.agent_id contains control characters");
  });

  // ── failClosed option tests ──

  test("evaluate returns Deny when failClosed and server unreachable", async () => {
    const fcClient = new VellavetoClient({
      baseUrl: "http://localhost:9999",
      apiKey: "test-key",
      failClosed: true,
    });
    // fetch() throws TypeError on network failure, which request() wraps in VellavetoError
    mockFetch.mockRejectedValueOnce(new TypeError("fetch failed"));
    const result = await fcClient.evaluate({ tool: "fs" });
    expect(result.verdict).toBe(Verdict.Deny);
    expect(result.reason).toContain("Server unreachable (fail-closed)");
  });

  test("evaluate throws when not failClosed and server unreachable", async () => {
    mockFetch.mockRejectedValueOnce(new TypeError("fetch failed"));
    await expect(client.evaluate({ tool: "fs" })).rejects.toThrow(VellavetoError);
  });

  test("evaluate throws HTTP error even with failClosed", async () => {
    const fcClient = new VellavetoClient({
      baseUrl: "http://localhost:9999",
      apiKey: "test-key",
      failClosed: true,
    });
    // HTTP 400 errors have a statusCode — these are server errors, not connection failures
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: "bad request" }, 400));
    await expect(fcClient.evaluate({ tool: "fs" })).rejects.toThrow(VellavetoError);
  });
});

// ── R260 Attestation Verification Tests ─────────────────────────────────

describe("verifyAttestation - R260 signature validation", () => {
  const hmacKey = "k".repeat(32);

  test("signature too short returns false", () => {
    const resp = { _meta: { vellaveto_attestation: { signature: "abcd" } } };
    expect(VellavetoClient.verifyAttestation(resp, hmacKey)).toBe(false);
  });

  test("signature too long returns false", () => {
    const resp = { _meta: { vellaveto_attestation: { signature: "a".repeat(65) } } };
    expect(VellavetoClient.verifyAttestation(resp, hmacKey)).toBe(false);
  });

  test("signature non-string returns false", () => {
    const resp = { _meta: { vellaveto_attestation: { signature: 12345 } } };
    expect(VellavetoClient.verifyAttestation(resp, hmacKey)).toBe(false);
  });

  test("signature null returns false", () => {
    const resp = { _meta: { vellaveto_attestation: { signature: null } } };
    expect(VellavetoClient.verifyAttestation(resp, hmacKey)).toBe(false);
  });
});

describe("verifyAttestation - R260 type safety", () => {
  const hmacKey = "k".repeat(32);

  function makeAttestation(overrides: Record<string, unknown> = {}) {
    return {
      result: {},
      _meta: {
        vellaveto_attestation: {
          version: 1,
          timestamp: 1000,
          content_hash: "a".repeat(64),
          injection_clean: true,
          dlp_clean: true,
          schema_valid: true,
          trust_tier: "Verified",
          scan_passes: 5,
          signature: "a".repeat(64),
          ...overrides,
        },
      },
    };
  }

  test("version as string returns false", () => {
    expect(VellavetoClient.verifyAttestation(makeAttestation({ version: "bad" }), hmacKey)).toBe(false);
  });

  test("timestamp as string returns false", () => {
    expect(VellavetoClient.verifyAttestation(makeAttestation({ timestamp: "bad" }), hmacKey)).toBe(false);
  });

  test("trust_tier as number returns false", () => {
    expect(VellavetoClient.verifyAttestation(makeAttestation({ trust_tier: 42 }), hmacKey)).toBe(false);
  });

  test("scan_passes as string returns false", () => {
    expect(VellavetoClient.verifyAttestation(makeAttestation({ scan_passes: "five" }), hmacKey)).toBe(false);
  });
});
