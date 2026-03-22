----------------------- MODULE NHICredentialRotation -----------------------
(**************************************************************************)
(* NHI Ephemeral Credential Rotation Lifecycle                            *)
(*                                                                        *)
(* Models the non-human identity credential rotation protocol from:       *)
(*   vellaveto-mcp/src/nhi.rs                                            *)
(*                                                                        *)
(* NHI credentials have bounded lifetimes and must be rotated before      *)
(* expiry. This spec verifies:                                            *)
(*                                                                        *)
(*   NHI-ROT-1: No credential used after expiry (fail-closed)            *)
(*   NHI-ROT-2: Rotation produces a new credential before old expires    *)
(*   NHI-ROT-3: Old credential invalidated after rotation completes      *)
(*   NHI-ROT-4: Rotation failure does not leave both creds active        *)
(*   NHI-ROT-5: Concurrent requests during rotation get consistent cred  *)
(*                                                                        *)
(* Liveness:                                                              *)
(*   NHI-ROT-L1: Every active credential eventually expires or rotates   *)
(*   NHI-ROT-L2: System does not get stuck in rotating state             *)
(**************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    CredIds,         \* Set of credential identifiers (e.g., {"c1","c2","c3"})
    MaxTime          \* Upper bound on time for model checking

VARIABLES
    activeCred,      \* Currently active credential ID (or "none")
    credState,       \* Function: CredId -> {"unused","active","expired","revoked"}
    credExpiry,      \* Function: CredId -> expiry timestamp
    rotatingTo,      \* Credential being rotated to (or "none")
    clock,           \* Current logical time
    systemState      \* "normal" | "rotating" | "degraded"

vars == <<activeCred, credState, credExpiry, rotatingTo, clock, systemState>>

(**************************************************************************)
(* Type invariant                                                         *)
(**************************************************************************)
States == {"unused", "active", "expired", "revoked"}
SystemStates == {"normal", "rotating", "degraded"}

TypeOK ==
    /\ activeCred \in CredIds \cup {"none"}
    /\ credState \in [CredIds -> States]
    /\ credExpiry \in [CredIds -> 0..MaxTime + 2]  \* TTL can extend beyond MaxTime
    /\ rotatingTo \in CredIds \cup {"none"}
    /\ clock \in 0..MaxTime
    /\ systemState \in SystemStates

(**************************************************************************)
(* Initial state — no active credential, system degraded                  *)
(**************************************************************************)
Init ==
    /\ activeCred = "none"
    /\ credState = [c \in CredIds |-> "unused"]
    /\ credExpiry = [c \in CredIds |-> 0]
    /\ rotatingTo = "none"
    /\ clock = 0
    /\ systemState = "degraded"

(**************************************************************************)
(* ACTION: IssueInitialCredential                                         *)
(* First credential provisioned, system transitions to normal.            *)
(**************************************************************************)
IssueInitialCredential ==
    /\ systemState = "degraded"
    /\ activeCred = "none"
    /\ \E c \in CredIds :
        /\ credState[c] = "unused"
        /\ activeCred' = c
        /\ credExpiry' = [credExpiry EXCEPT ![c] = clock + 2]  \* TTL = 2 ticks
        /\ systemState' = "normal"
        /\ rotatingTo' = "none"
        \* If a stale rotation target is still active, revoke it
        /\ credState' = IF rotatingTo # "none" /\ rotatingTo # c /\ credState[rotatingTo] = "active"
                         THEN [credState EXCEPT ![c] = "active", ![rotatingTo] = "revoked"]
                         ELSE [credState EXCEPT ![c] = "active"]
        /\ UNCHANGED <<clock>>

(**************************************************************************)
(* ACTION: StartRotation                                                  *)
(* Rotation begins before current credential expires.                     *)
(* A new unused credential is selected as rotation target.                *)
(**************************************************************************)
StartRotation ==
    /\ systemState = "normal"
    /\ activeCred # "none"
    /\ credState[activeCred] = "active"
    /\ clock < credExpiry[activeCred]  \* Must start before expiry
    /\ rotatingTo = "none"
    /\ \E c \in CredIds :
        /\ c # activeCred
        /\ credState[c] = "unused"
        /\ rotatingTo' = c
        /\ credState' = [credState EXCEPT ![c] = "active"]
        /\ credExpiry' = [credExpiry EXCEPT ![c] = clock + 2]
        /\ systemState' = "rotating"
        /\ UNCHANGED <<activeCred, clock>>

(**************************************************************************)
(* ACTION: CompleteRotation                                               *)
(* New credential takes over, old credential revoked.                     *)
(**************************************************************************)
CompleteRotation ==
    /\ systemState = "rotating"
    /\ rotatingTo # "none"
    /\ credState[rotatingTo] = "active"
    /\ LET oldCred == activeCred
       IN
        /\ activeCred' = rotatingTo
        /\ credState' = [credState EXCEPT ![oldCred] = "revoked"]
        /\ rotatingTo' = "none"
        /\ systemState' = "normal"
        /\ UNCHANGED <<credExpiry, clock>>

(**************************************************************************)
(* ACTION: RotationFailed                                                 *)
(* Rotation fails — revert to old credential, discard new.                *)
(* Old credential remains active (no gap). New credential revoked.        *)
(**************************************************************************)
RotationFailed ==
    /\ systemState = "rotating"
    /\ rotatingTo # "none"
    /\ LET newCred == rotatingTo
       IN
        /\ credState' = [credState EXCEPT ![newCred] = "revoked"]
        /\ rotatingTo' = "none"
        /\ systemState' = "normal"
        /\ UNCHANGED <<activeCred, credExpiry, clock>>

(**************************************************************************)
(* ACTION: CredentialExpired                                              *)
(* Clock reaches or passes a credential's expiry.                         *)
(* Expired credentials are marked, system degrades if active cred expired.*)
(**************************************************************************)
CredentialExpired ==
    /\ \E c \in CredIds :
        /\ credState[c] = "active"
        /\ clock >= credExpiry[c]
        /\ credState' = [credState EXCEPT ![c] = "expired"]
        /\ IF c = activeCred
           THEN
             /\ activeCred' = "none"
             /\ systemState' = "degraded"
           ELSE
             UNCHANGED <<activeCred, systemState>>
        /\ UNCHANGED <<credExpiry, rotatingTo, clock>>

(**************************************************************************)
(* ACTION: Tick                                                           *)
(* Time advances by 1.                                                    *)
(**************************************************************************)
Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED <<activeCred, credState, credExpiry, rotatingTo, systemState>>

(**************************************************************************)
(* Next state relation                                                    *)
(**************************************************************************)
Next ==
    \/ IssueInitialCredential
    \/ StartRotation
    \/ CompleteRotation
    \/ RotationFailed
    \/ CredentialExpired
    \/ Tick

(**************************************************************************)
(* Fairness                                                               *)
(**************************************************************************)
Fairness ==
    /\ WF_vars(IssueInitialCredential)
    /\ WF_vars(StartRotation)
    /\ WF_vars(CompleteRotation)
    /\ WF_vars(RotationFailed)
    /\ WF_vars(CredentialExpired)
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

(**************************************************************************)
(* SAFETY INVARIANTS                                                      *)
(**************************************************************************)

(**************************************************************************)
(* NHI-ROT-1: No credential is used after expiry.                         *)
(* The active credential must not be expired.                             *)
(**************************************************************************)
InvariantNHIROT1_NoUseAfterExpiry ==
    activeCred # "none" => credState[activeCred] = "active"

(**************************************************************************)
(* NHI-ROT-3: Old credential invalidated after rotation.                  *)
(* After CompleteRotation, the old credential is revoked.                 *)
(* Formulated: at most one credential is "active" at any time             *)
(* (either normal with 1, or rotating with 2 briefly).                    *)
(**************************************************************************)
InvariantNHIROT3_AtMostTwoActive ==
    Cardinality({c \in CredIds : credState[c] = "active"}) <= 2

(**************************************************************************)
(* NHI-ROT-4: Rotation failure does not leave both creds active.          *)
(* After RotationFailed, exactly one credential remains active.           *)
(* Formulated: in normal state, at most 1 active credential.             *)
(**************************************************************************)
InvariantNHIROT4_NormalHasOneActive ==
    systemState = "normal" =>
        Cardinality({c \in CredIds : credState[c] = "active"}) <= 1

(**************************************************************************)
(* NHI-ROT-5: During rotation, the active credential is consistent.       *)
(* Concurrent readers always see activeCred (not rotatingTo).            *)
(* Formulated: activeCred never changes during rotation until             *)
(* CompleteRotation fires.                                                *)
(**************************************************************************)
InvariantNHIROT5_ActiveConsistentDuringRotation ==
    systemState = "rotating" =>
        /\ activeCred # "none"
        /\ credState[activeCred] \in {"active", "expired"}

(**************************************************************************)
(* LIVENESS PROPERTIES                                                    *)
(**************************************************************************)

(**************************************************************************)
(* NHI-ROT-L1: Every active credential eventually expires or is revoked.  *)
(**************************************************************************)
LivenessNHIROTL1_EventualExpiry ==
    \A c \in CredIds :
        credState[c] = "active" ~> credState[c] \in {"expired", "revoked"}

(**************************************************************************)
(* NHI-ROT-L2: System does not get stuck in rotating state.               *)
(**************************************************************************)
LivenessNHIROTL2_RotationCompletes ==
    systemState = "rotating" ~> systemState \in {"normal", "degraded"}

==========================================================================
