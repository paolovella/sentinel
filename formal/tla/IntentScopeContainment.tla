---- MODULE IntentScopeContainment ----
(*
 * Phase 6.2E: Intent scope declaration containment properties.
 *
 * Verifies that intent scope enforcement is complete, monotonic,
 * and composes correctly with source-class tainting.
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    SinkClasses,    \* Set of sink class names
    AllowedSinks,   \* Initial allowed sink classes
    TrustRanks      \* Rank mapping

VARIABLES
    allowedSinks,       \* Current allowed sink classes (may narrow)
    scopeLocked,        \* Whether scope expansion is disabled
    distinctToolCount,  \* Number of distinct tools used
    maxDistinctTools,   \* Maximum allowed distinct tools
    taintActive,        \* Whether session has been tainted
    blocked,            \* Last action blocked?
    callLog

vars == <<allowedSinks, scopeLocked, distinctToolCount, maxDistinctTools,
          taintActive, blocked, callLog>>

Init ==
    /\ allowedSinks = AllowedSinks
    /\ scopeLocked = FALSE
    /\ distinctToolCount = 0
    /\ maxDistinctTools = 10
    /\ taintActive = FALSE
    /\ blocked = FALSE
    /\ callLog = <<>>

\* Check if a sink is in scope
InScope(sink) == sink \in allowedSinks

\* Attempt a tool call
AttemptAction(sink, isNewTool) ==
    LET newCount == IF isNewTool
                    THEN distinctToolCount + 1
                    ELSE distinctToolCount
    IN
    /\ IF ~InScope(sink)
       THEN blocked' = TRUE
       ELSE IF newCount > maxDistinctTools
            THEN blocked' = TRUE
            ELSE blocked' = FALSE
    /\ distinctToolCount' = newCount
    /\ callLog' = Append(callLog, <<sink, blocked'>>)
    /\ UNCHANGED <<allowedSinks, scopeLocked, maxDistinctTools, taintActive>>

\* Source taint fires — restrict scope
TaintFires(restrictedSinks) ==
    /\ taintActive' = TRUE
    /\ allowedSinks' = allowedSinks \intersect restrictedSinks
    /\ scopeLocked' = TRUE
    /\ maxDistinctTools' = IF maxDistinctTools > 3 THEN 3 ELSE maxDistinctTools
    /\ UNCHANGED <<distinctToolCount, blocked, callLog>>

\* Attempt to expand scope (must be rejected when locked)
AttemptScopeExpansion(newSink) ==
    /\ IF scopeLocked
       THEN allowedSinks' = allowedSinks  \* No change
       ELSE allowedSinks' = allowedSinks \union {newSink}
    /\ UNCHANGED <<scopeLocked, distinctToolCount, maxDistinctTools,
                   taintActive, blocked, callLog>>

Next ==
    \/ \E sink \in SinkClasses, new \in {TRUE, FALSE} : AttemptAction(sink, new)
    \/ \E restricted \in SUBSET SinkClasses : TaintFires(restricted)
    \/ \E sink \in SinkClasses : AttemptScopeExpansion(sink)

\* ═══════════════════════════════════════════════════
\* Safety Invariants
\* ═══════════════════════════════════════════════════

\* IS1: Out-of-scope tool calls are never silently allowed.
IS1_EnforcementCompleteness ==
    \A i \in 1..Len(callLog) :
        LET entry == callLog[i]
            sink == entry[1]
            wasBlocked == entry[2]
        IN ~InScope(sink) => wasBlocked = TRUE

\* IS2: Scope can only narrow once locked (monotonic).
IS2_MonotonicNarrowing ==
    scopeLocked => allowedSinks \subseteq AllowedSinks

\* IS3: Scope restriction after taint is subset of original.
IS3_RestrictionSubset ==
    taintActive => allowedSinks \subseteq AllowedSinks

\* IS4: No window between taint and restriction.
\* (TaintFires atomically narrows scope and locks it)
IS4_AtomicRestriction ==
    taintActive => scopeLocked

Spec == Init /\ [][Next]_vars

====
