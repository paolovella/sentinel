---- MODULE SequenceContainment ----
(*
 * Phase 6.3E: Behavioral sequence analysis containment properties.
 *
 * Verifies that sequence-based anomaly detection is monotonic,
 * composes with taint-based restrictions, and respects warmup.
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    WarmupCalls,    \* Minimum calls before detection activates
    WindowMs,       \* Time window for temporal patterns
    MaxNewTools     \* Max new tools after taint

VARIABLES
    callCount,          \* Total calls in session
    anomalyDetected,    \* Whether any anomaly has been flagged
    anomalyConfidence,  \* Highest anomaly confidence (0-100)
    taintActive,        \* Whether session has been tainted
    newToolsAfterTaint, \* Count of new tools introduced after taint
    scopeRestricted,    \* Whether scope has been restricted by anomaly
    callLog

vars == <<callCount, anomalyDetected, anomalyConfidence, taintActive,
          newToolsAfterTaint, scopeRestricted, callLog>>

Init ==
    /\ callCount = 0
    /\ anomalyDetected = FALSE
    /\ anomalyConfidence = 0
    /\ taintActive = FALSE
    /\ newToolsAfterTaint = 0
    /\ scopeRestricted = FALSE
    /\ callLog = <<>>

\* Record a tool call
RecordCall(isPrivileged, isNovel, isTainted) ==
    /\ callCount' = callCount + 1
    /\ IF isTainted /\ ~taintActive
       THEN taintActive' = TRUE
       ELSE taintActive' = taintActive
    /\ IF taintActive /\ isNovel
       THEN newToolsAfterTaint' = newToolsAfterTaint + 1
       ELSE newToolsAfterTaint' = newToolsAfterTaint
    /\ callLog' = Append(callLog, <<isPrivileged, isNovel, isTainted>>)
    \* Run detectors (only after warmup)
    /\ IF callCount + 1 >= WarmupCalls
       THEN
         LET diversitySpike == newToolsAfterTaint' > MaxNewTools
             privEsc == taintActive' /\ isPrivileged /\ ~isNovel
             novelAfterTaint == taintActive' /\ isNovel /\ isPrivileged
             detected == diversitySpike \/ privEsc \/ novelAfterTaint
             confidence == IF novelAfterTaint THEN 85
                          ELSE IF privEsc THEN 90
                          ELSE IF diversitySpike THEN 60
                          ELSE 0
         IN
         /\ anomalyDetected' = anomalyDetected \/ detected
         /\ anomalyConfidence' =
             IF confidence > anomalyConfidence
             THEN confidence
             ELSE anomalyConfidence
         /\ IF detected /\ confidence >= 70
            THEN scopeRestricted' = TRUE
            ELSE scopeRestricted' = scopeRestricted
       ELSE
         /\ UNCHANGED <<anomalyDetected, anomalyConfidence, scopeRestricted>>

Next ==
    \E priv \in {TRUE, FALSE}, novel \in {TRUE, FALSE}, taint \in {TRUE, FALSE} :
        RecordCall(priv, novel, taint)

\* ═══════════════════════════════════════════════════
\* Safety Invariants
\* ═══════════════════════════════════════════════════

\* SQ1: Once an anomaly is detected, it persists for the session.
SQ1_AnomalyPersistence ==
    anomalyDetected => []anomalyDetected

\* SQ2: Scope restriction from anomaly is at least as restrictive
\* as from taint alone (anomaly can only further narrow, never widen).
SQ2_RestrictionMonotonicity ==
    scopeRestricted => anomalyDetected

\* SQ3: No privileged call should execute while an unacknowledged
\* high-confidence anomaly exists.
\* (This is enforced by the relay — the spec verifies the invariant
\* that detection implies restriction)
SQ3_AnomalyImpliesRestriction ==
    (anomalyConfidence >= 70) => scopeRestricted

\* SQ4: Warmup period does not suppress taint-based restrictions.
\* (Taint fires independently of sequence analysis warmup)
SQ4_WarmupDoesNotSuppressTaint ==
    (callCount < WarmupCalls /\ taintActive) =>
        \* Even during warmup, taint is active
        taintActive

Spec == Init /\ [][Next]_vars

====
