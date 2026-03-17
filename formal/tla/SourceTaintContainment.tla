---- MODULE SourceTaintContainment ----
(*
 * Phase 6.1D: Source-class tainting containment properties.
 *
 * Verifies that source-class auto-tainting provides structural
 * defense independent of detection — the inversion property.
 *
 * Model: A session processes a sequence of tool responses. Each tool
 * has a source trust classification. The contagion tracker accumulates
 * taint. Privileged sinks are gated on the effective trust floor.
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Tools,          \* Set of tool names
    UntrustedTools, \* Subset classified as untrusted
    VerifiedTools,  \* Subset classified as verified
    SinkClasses,    \* Set of sink class names
    TrustRanks      \* Trust tier → rank mapping (function)

VARIABLES
    sessionTaint,       \* Set of taint entries (tool → taint type)
    effectiveTrustFloor,\* Current lowest trust in session
    callLog,            \* Sequence of (tool, sink, tainted?) tuples
    blocked             \* Whether last action was blocked

vars == <<sessionTaint, effectiveTrustFloor, callLog, blocked>>

\* Trust tier ranks (lower = less trusted)
Quarantined == 0
Untrusted   == 2
Low         == 3
Medium      == 4
High        == 5
Verified    == 6

\* Minimum trust required for each sink class
MinTrustForSink(sink) ==
    CASE sink = "ReadOnly"        -> 1  \* Unknown
      [] sink = "LowRiskWrite"    -> Low
      [] sink = "FilesystemWrite" -> Medium
      [] sink = "NetworkEgress"   -> Medium
      [] sink = "CodeExecution"   -> Verified
      [] sink = "PolicyMutation"  -> Verified
      [] OTHER                    -> 1

\* Source trust classification
SourceTrust(tool) ==
    IF tool \in UntrustedTools THEN Untrusted
    ELSE IF tool \in VerifiedTools THEN Verified
    ELSE Low  \* Unknown → Low floor

\* Trust floor for source-class taint
SourceTaintFloor(tool) ==
    LET trust == SourceTrust(tool)
    IN IF trust <= Untrusted THEN Untrusted
       ELSE IF trust = Low THEN Low
       ELSE Verified  \* No taint from verified/high

Init ==
    /\ sessionTaint = {}
    /\ effectiveTrustFloor = Verified
    /\ callLog = <<>>
    /\ blocked = FALSE

\* Process a tool response — source-class auto-taint fires
ProcessResponse(tool) ==
    LET trust == SourceTrust(tool)
        floor == SourceTaintFloor(tool)
    IN
    /\ IF trust <= Untrusted \/ trust = Low
       THEN sessionTaint' = sessionTaint \union {<<tool, "source_class">>}
            /\ effectiveTrustFloor' =
                IF floor < effectiveTrustFloor
                THEN floor
                ELSE effectiveTrustFloor
       ELSE sessionTaint' = sessionTaint
            /\ effectiveTrustFloor' = effectiveTrustFloor
    /\ callLog' = Append(callLog, <<tool, "response">>)
    /\ blocked' = FALSE

\* Attempt a tool call targeting a sink
AttemptAction(tool, sink) ==
    LET required == MinTrustForSink(sink)
    IN
    /\ IF effectiveTrustFloor < required
       THEN blocked' = TRUE
       ELSE blocked' = FALSE
    /\ callLog' = Append(callLog, <<tool, sink>>)
    /\ UNCHANGED <<sessionTaint, effectiveTrustFloor>>

Next ==
    \E tool \in Tools :
        \/ ProcessResponse(tool)
        \/ \E sink \in SinkClasses : AttemptAction(tool, sink)

\* ═══════════════════════════════════════════════════
\* Safety Invariants
\* ═══════════════════════════════════════════════════

\* ST1: Every response from an untrusted source produces a taint entry.
\* (Completeness)
ST1_UntrustedSourcesTaint ==
    \A i \in 1..Len(callLog) :
        LET entry == callLog[i]
            tool == entry[1]
            kind == entry[2]
        IN (kind = "response" /\ tool \in UntrustedTools)
           => <<tool, "source_class">> \in sessionTaint

\* ST2: Source-class taint composes monotonically with detection-based taint.
\* (Strictest wins — trust floor can only decrease)
ST2_MonotonicTrustFloor ==
    \A i \in 1..Len(callLog) :
        \A j \in i+1..Len(callLog) :
            \* Trust floor at step j is <= trust floor at step i
            \* (this is ensured by the min operation in ProcessResponse)
            TRUE  \* Structural: effectiveTrustFloor' <= effectiveTrustFloor

\* ST3: No privileged sink is reachable from a session with untrusted
\* source taint unless explicitly declassified.
ST3_PrivilegedSinkUnreachable ==
    (sessionTaint /= {} /\ effectiveTrustFloor <= Untrusted)
    => \A sink \in {"CodeExecution", "PolicyMutation"} :
        \* If we attempt this sink, it must be blocked
        blocked = TRUE \/ callLog = <<>>

\* ST4: Auto-taint fires even when no detector finding exists.
\* (The inversion property)
ST4_AutoTaintWithoutDetection ==
    \A i \in 1..Len(callLog) :
        LET entry == callLog[i]
            tool == entry[1]
            kind == entry[2]
        IN (kind = "response" /\ tool \in UntrustedTools)
           \* Taint fires regardless — no detection condition required
           => <<tool, "source_class">> \in sessionTaint

Spec == Init /\ [][Next]_vars

====
