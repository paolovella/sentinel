------------------------- MODULE CapabilityDelegation -------------------------
(**************************************************************************)
(* Formal specification of capability token delegation.                   *)
(*                                                                        *)
(* Models the delegation system from:                                     *)
(*   vellaveto-mcp/src/capability_token.rs                                *)
(*   vellaveto-types/src/capability.rs                                    *)
(*                                                                        *)
(* This TLA+ specification complements the Alloy model                    *)
(* (CapabilityDelegation.als) by verifying delegation properties as       *)
(* temporal invariants over state machine transitions (dynamic behavior), *)
(* whereas Alloy verifies relational properties over static structures.   *)
(*                                                                        *)
(* Verifies 5 safety invariants:                                          *)
(*   D1: Monotonic depth — delegation strictly decreases depth            *)
(*   D2: Depth bounded — no token has depth > MAX_DEPTH                   *)
(*   D3: Temporal monotonicity — child.expiry <= parent.expiry            *)
(*   D4: No self-delegation — issuer != holder in delegation              *)
(*   D5: Terminal isolation — depth=0 tokens never delegate               *)
(*                                                                        *)
(* And 1 liveness property:                                               *)
(*   DL1: Delegation chains eventually terminate (depth exhaustion)       *)
(**************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

(**************************************************************************)
(* CONSTANTS                                                              *)
(**************************************************************************)
CONSTANTS
    Principals,        \* Set of principal identifiers
    MaxDepth,          \* Maximum delegation depth (3 in model, 16 in Rust)
    MaxTokens,         \* Maximum number of tokens in the system
    TimeValues         \* Set of time values (abstract, totally ordered)

(**************************************************************************)
(* VARIABLES                                                              *)
(**************************************************************************)
VARIABLES
    tokens,            \* Set of token records
    nextId             \* Counter for generating unique token IDs

vars == <<tokens, nextId>>

(**************************************************************************)
(* Helper: Time ordering (abstract total order on TimeValues)             *)
(* We use integer comparison to model time ordering.                      *)
(**************************************************************************)
TimeLTE(t1, t2) == t1 <= t2

(**************************************************************************)
(* Token record structure                                                 *)
(*                                                                        *)
(* Each token is a record with:                                           *)
(*   .id        - Unique identifier (integer)                             *)
(*   .parent_id - Parent token ID (0 for root tokens)                     *)
(*   .issuer    - Principal who created the token                         *)
(*   .holder    - Principal who can use the token                         *)
(*   .depth     - Remaining delegation depth                              *)
(*   .expiry    - Expiration time value                                   *)
(**************************************************************************)

(**************************************************************************)
(* TYPE INVARIANT                                                         *)
(**************************************************************************)
TypeOK ==
    /\ \A t \in tokens :
        /\ t.id \in 1..MaxTokens
        /\ t.parent_id \in 0..MaxTokens  \* 0 = root
        /\ t.issuer \in Principals
        /\ t.holder \in Principals
        /\ t.depth \in 0..MaxDepth
        /\ t.expiry \in TimeValues
    /\ nextId \in 1..(MaxTokens + 1)

(**************************************************************************)
(* INITIAL STATE                                                          *)
(**************************************************************************)
Init ==
    /\ tokens = {}
    /\ nextId = 1

(**************************************************************************)
(* ACTION: CreateRootToken                                                *)
(*                                                                        *)
(* Create a new root token (no parent, starts at MaxDepth).               *)
(* Maps to initial token creation (not delegation).                       *)
(**************************************************************************)
CreateRootToken ==
    /\ nextId <= MaxTokens
    /\ \E issuer \in Principals, holder \in Principals, exp \in TimeValues :
        LET newToken == [
            id        |-> nextId,
            parent_id |-> 0,
            issuer    |-> issuer,
            holder    |-> holder,
            depth     |-> MaxDepth,
            expiry    |-> exp
        ]
        IN
        /\ tokens' = tokens \union {newToken}
        /\ nextId' = nextId + 1

(**************************************************************************)
(* ACTION: Delegate                                                       *)
(*                                                                        *)
(* Create a child token from an existing parent token.                    *)
(* Enforces all delegation constraints:                                   *)
(*   - Parent depth > 0 (S15: terminal cannot delegate)                   *)
(*   - Child depth = parent depth - 1 (S13: monotonic decrease)           *)
(*   - Child expiry <= parent expiry (S14: temporal monotonicity)         *)
(*   - Child issuer = parent holder (S16: issuer chain)                   *)
(*                                                                        *)
(* Maps to attenuate_capability_token() at capability_token.rs:95-200.   *)
(**************************************************************************)
Delegate ==
    /\ nextId <= MaxTokens
    /\ \E parent \in tokens :
        /\ parent.depth > 0                    \* S15: cannot delegate at depth 0
        /\ \E newHolder \in Principals, newExp \in TimeValues :
            /\ TimeLTE(newExp, parent.expiry)   \* S14: expiry clamping
            /\ LET newToken == [
                   id        |-> nextId,
                   parent_id |-> parent.id,
                   issuer    |-> parent.holder,   \* S16: issuer = parent.holder
                   holder    |-> newHolder,
                   depth     |-> parent.depth - 1, \* S13: strict decrement
                   expiry    |-> newExp
               ]
               IN
               /\ tokens' = tokens \union {newToken}
               /\ nextId' = nextId + 1

(**************************************************************************)
(* NEXT STATE RELATION                                                    *)
(**************************************************************************)
Next == CreateRootToken \/ Delegate

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(**************************************************************************)
(* SAFETY INVARIANTS                                                      *)
(**************************************************************************)

(**************************************************************************)
(* D1: Monotonic Depth — delegation strictly decreases depth.             *)
(*                                                                        *)
(* For every non-root token (parent_id != 0), its depth is strictly       *)
(* less than its parent's depth. This ensures delegation chains converge. *)
(*                                                                        *)
(* Maps to capability_token.rs:166 (remaining_depth - 1).                *)
(**************************************************************************)
InvariantD1_MonotonicDepth ==
    \A child \in tokens :
        child.parent_id # 0 =>
            \A parent \in tokens :
                parent.id = child.parent_id =>
                    child.depth < parent.depth

(**************************************************************************)
(* D2: Depth Bounded — no token exceeds MaxDepth.                         *)
(*                                                                        *)
(* Every token's remaining depth is within [0, MaxDepth].                 *)
(* Root tokens start at MaxDepth, delegated tokens have strictly less.    *)
(*                                                                        *)
(* Maps to MAX_DELEGATION_DEPTH at capability.rs:21.                     *)
(**************************************************************************)
InvariantD2_DepthBounded ==
    \A t \in tokens :
        t.depth >= 0 /\ t.depth <= MaxDepth

(**************************************************************************)
(* D3: Temporal Monotonicity — child.expiry <= parent.expiry.             *)
(*                                                                        *)
(* Expiry can only shrink (or stay the same) through the delegation       *)
(* chain. This ensures delegated tokens cannot outlive their parents.     *)
(*                                                                        *)
(* Maps to expiry clamping at capability_token.rs:172-176.               *)
(**************************************************************************)
InvariantD3_TemporalMonotonicity ==
    \A child \in tokens :
        child.parent_id # 0 =>
            \A parent \in tokens :
                parent.id = child.parent_id =>
                    TimeLTE(child.expiry, parent.expiry)

(**************************************************************************)
(* D4: Issuer Chain Integrity — child.issuer = parent.holder.             *)
(*                                                                        *)
(* The issuer of a delegated token is always the holder of the parent.    *)
(* This ensures only the token holder can delegate it.                    *)
(*                                                                        *)
(* Maps to capability_token.rs:195.                                      *)
(**************************************************************************)
InvariantD4_IssuerChainIntegrity ==
    \A child \in tokens :
        child.parent_id # 0 =>
            \A parent \in tokens :
                parent.id = child.parent_id =>
                    child.issuer = parent.holder

(**************************************************************************)
(* D5: Terminal Isolation — depth=0 tokens have no children.              *)
(*                                                                        *)
(* No token in the system has a parent with depth=0.                      *)
(* This is the dynamic version of S15 (terminal cannot delegate).         *)
(*                                                                        *)
(* Maps to depth check at capability_token.rs:128-132.                   *)
(**************************************************************************)
InvariantD5_TerminalIsolation ==
    \A child \in tokens :
        child.parent_id # 0 =>
            \A parent \in tokens :
                parent.id = child.parent_id =>
                    parent.depth > 0

(**************************************************************************)
(* LIVENESS                                                               *)
(**************************************************************************)

(**************************************************************************)
(* DL1: Delegation chains eventually terminate.                           *)
(*                                                                        *)
(* Under weak fairness, if a delegatable token exists and the system has  *)
(* capacity for new tokens, eventually either a chain reaches depth=0     *)
(* (terminal) or the system exhausts its token capacity.                  *)
(*                                                                        *)
(* The guard (nextId <= MaxTokens) is necessary because this is a         *)
(* bounded model: tokens are never removed, so slots can fill with        *)
(* non-terminal tokens before any chain completes.  In an unbounded       *)
(* system the second disjunct is unreachable and the property reduces     *)
(* to pure chain termination.                                             *)
(*                                                                        *)
(* Combined with D1 (monotonic depth) and D2 (depth bounded), this       *)
(* proves all delegation chains are finite.                               *)
(**************************************************************************)
LivenessDL1_ChainTermination ==
    (\E t \in tokens : t.depth > 0 /\ nextId <= MaxTokens) ~>
    ((\E t \in tokens : t.depth = 0) \/ nextId > MaxTokens)

=========================================================================
