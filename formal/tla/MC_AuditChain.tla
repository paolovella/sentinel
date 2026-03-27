---------------------- MODULE MC_AuditChain ----------------------
(**************************************************************************)
(* Model companion for AuditChain.tla                                     *)
(*                                                                        *)
(* Provides concrete constant values for TLC model checking.              *)
(* 3 entries × 3 IDs × 3 hashes is sufficient because:                   *)
(*   - Chain linkage is pairwise (entry[n] references entry[n-1])         *)
(*   - Sequence monotonicity is pairwise                                  *)
(*   - Hash uniqueness needs |HashValues| >= MaxEntries                   *)
(*   - Rotation continuity needs >= 1 rotation                            *)
(*                                                                        *)
(* State constraint bounds nextSequence and rotationCount to keep the     *)
(* state space finite. Without this, TLC explores infinitely many         *)
(* rotation cycles (nextSequence and rotationCount are unbounded Nat).    *)
(**************************************************************************)
EXTENDS AuditChain

const_MaxEntries == 3
const_EntryIds == {"e1", "e2", "e3"}
const_HashValues == {"h1", "h2", "h3"}

(* Bound unbounded Nat counters to keep the state space finite.           *)
(* nextSequence <= 2 * MaxEntries covers: fill log, rotate, fill again.   *)
(* rotationCount <= 2 covers the cross-rotation chain linkage property.   *)
StateConstraint ==
    /\ nextSequence <= 6
    /\ rotationCount <= 2

=========================================================================
