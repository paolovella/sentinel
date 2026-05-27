"""
Vellaveto SDK type definitions.

These types mirror the Rust types in vellaveto-types for interoperability.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


class Verdict(Enum):
    """Policy evaluation verdict."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Action:
    """
    Represents a tool call action to be evaluated by Vellaveto.

    Attributes:
        tool: The tool name (e.g., "filesystem", "http")
        function: The function being called (e.g., "read_file", "fetch")
        parameters: Tool call parameters as a dictionary
        target_paths: File paths the tool will access (extracted from parameters)
        target_domains: Network domains the tool will access
        resolved_ips: Resolved IP addresses for network targets
    """
    tool: str
    function: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_paths: List[str] = field(default_factory=list)
    target_domains: List[str] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "tool": self.tool,
            "function": self.function,
            "parameters": self.parameters,
            "target_paths": self.target_paths,
            "target_domains": self.target_domains,
            "resolved_ips": self.resolved_ips,
        }


@dataclass
class EvaluationResult:
    """
    Result of a policy evaluation.

    Attributes:
        verdict: The policy decision (allow, deny, require_approval)
        reason: Human-readable reason for the decision
        policy_id: ID of the policy that matched (if any)
        policy_name: Name of the policy that matched (if any)
        approval_id: Approval ID if verdict is require_approval
        trace: Evaluation trace data (if tracing enabled)
    """
    verdict: Verdict
    reason: Optional[str] = None
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    approval_id: Optional[str] = None
    trace: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Normalize direct string construction to the declared Verdict enum."""
        if isinstance(self.verdict, str):
            try:
                self.verdict = Verdict(self.verdict)
            except ValueError:
                self.verdict = Verdict.DENY

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvaluationResult":
        """Create from API response dictionary.

        SECURITY (FIND-SDK-002): Unknown verdict strings are mapped to DENY
        (fail-closed) instead of raising ValueError. A malicious or buggy server
        returning an unrecognized verdict must not crash the client.
        """
        verdict_str = data.get("verdict", "deny").lower()
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.DENY

        # SECURITY (FIND-R99-001): Validate response field types to prevent
        # type confusion from malicious/buggy servers. Non-string values for
        # string fields are discarded (fail-closed) rather than propagated.
        def _str_or_none(val: Any) -> Optional[str]:
            return val if isinstance(val, str) else None

        raw_trace = data.get("trace")
        trace = raw_trace if isinstance(raw_trace, dict) else None

        return cls(
            verdict=verdict,
            reason=_str_or_none(data.get("reason")),
            policy_id=_str_or_none(data.get("policy_id")),
            policy_name=_str_or_none(data.get("policy_name")),
            approval_id=_str_or_none(data.get("approval_id")),
            trace=trace,
        )


@dataclass
class EvaluationContext:
    """
    Context for policy evaluation.

    Attributes:
        session_id: Session identifier for stateful evaluation
        agent_id: Agent identifier for agent-specific policies
        tenant_id: Tenant identifier for multi-tenant deployments
        call_chain: List of previous tool calls in this chain
        metadata: Additional context metadata
    """
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    call_chain: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "call_chain": self.call_chain,
            "metadata": self.metadata,
        }


@dataclass
class DlpFinding:
    """
    Data Loss Prevention finding.

    Attributes:
        pattern_name: Name of the DLP pattern that matched
        field_path: JSON path where the secret was found
        redacted_value: Redacted version of the matched value
    """
    pattern_name: str
    field_path: str
    redacted_value: Optional[str] = None


@dataclass
class InjectionAlert:
    """
    Prompt injection detection alert.

    Attributes:
        pattern: The injection pattern that matched
        location: Where the injection was detected
        severity: Severity level (low, medium, high)
    """
    pattern: str
    location: str
    severity: str = "medium"


# ── ZK Audit Types (Phase 37) ───────────────────────────────────

@dataclass
class ZkBatchProof:
    """
    A batch ZK proof covering a range of audit entries.

    Attributes:
        proof: Hex-encoded Groth16 proof bytes
        batch_id: Unique batch identifier (UUID)
        entry_range: Inclusive range of entry sequence numbers (start, end)
        merkle_root: Hex-encoded Merkle root at batch end
        first_prev_hash: Hex-encoded prev_hash of first entry (public input)
        final_entry_hash: Hex-encoded entry_hash of last entry (public input)
        created_at: ISO 8601 timestamp when proof was created
        entry_count: Number of entries in the batch
    """
    proof: str
    batch_id: str
    entry_range: tuple
    merkle_root: str
    first_prev_hash: str
    final_entry_hash: str
    created_at: str
    entry_count: int


@dataclass
class ZkVerifyResult:
    """
    Result of verifying a ZK batch proof.

    Attributes:
        valid: Whether the proof is valid
        batch_id: The batch ID that was verified
        entry_range: The entry range that was verified (start, end)
        verified_at: ISO 8601 timestamp when verification was performed
        error: Error message if verification failed
    """
    valid: bool
    batch_id: str
    entry_range: tuple
    verified_at: str
    error: Optional[str] = None


@dataclass
class ZkSchedulerStatus:
    """
    Status of the ZK audit scheduler.

    Attributes:
        active: Whether the batch prover is active
        pending_witnesses: Number of pending witnesses awaiting batch proof
        completed_proofs: Number of completed batch proofs
        last_proved_sequence: Sequence number of the last proved entry
        last_proof_at: ISO 8601 timestamp of the last batch proof
    """
    active: bool
    pending_witnesses: int
    completed_proofs: int
    last_proved_sequence: Optional[int] = None
    last_proof_at: Optional[str] = None
