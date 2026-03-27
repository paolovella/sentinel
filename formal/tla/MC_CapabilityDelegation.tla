---- MODULE MC_CapabilityDelegation ----
(**************************************************************************)
(* Model companion for CapabilityDelegation.tla                           *)
(* Provides concrete constants for TLC model checking.                    *)
(*                                                                        *)
(* Reduced from 3 principals/6 tokens/4 times to 2 principals/4 tokens/  *)
(* 2 times with a cardinality constraint. The original configuration      *)
(* produced a state space > 10^8 states (powerset explosion on the        *)
(* tokens set), exceeding the 180-minute CI timeout.                      *)
(*                                                                        *)
(* MaxDepth=2 so a full chain (depth 2->1->0) needs 3 tokens, leaving    *)
(* room within the 4-token cardinality bound for the liveness property    *)
(* DL1 to be satisfied (chains can reach depth 0 without exhausting       *)
(* token slots).                                                          *)
(*                                                                        *)
(* 2 principals + depth 2 + 4 tokens is sufficient because:              *)
(*   - D1 (monotonic depth) is pairwise parent-child                     *)
(*   - D3 (temporal monotonicity) is pairwise parent-child               *)
(*   - D5 (terminal isolation) needs depth 0 reachable (depth 2 -> 0)    *)
(*   - DL1 (chain termination) needs at least one full chain             *)
(**************************************************************************)
EXTENDS CapabilityDelegation

const_Principals == {"alice", "bob"}

const_MaxDepth == 2

const_MaxTokens == 4

const_TimeValues == {1, 2}

(* Bound the tokens set cardinality to keep state space finite.           *)
(* Without this, TLC explores all subsets of possible token combinations. *)
StateConstraint == Cardinality(tokens) <= 4

=========================================================================
