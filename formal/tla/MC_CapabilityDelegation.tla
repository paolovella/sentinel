---- MODULE MC_CapabilityDelegation ----
(**************************************************************************)
(* Model companion for CapabilityDelegation.tla                           *)
(* Provides concrete constants for TLC model checking.                    *)
(*                                                                        *)
(* Reduced from 3 principals/6 tokens/4 times to 2 principals/4 tokens/  *)
(* 3 times with a cardinality constraint. The original configuration      *)
(* produced a state space > 10^8 states (powerset explosion on the        *)
(* tokens set), exceeding the 180-minute CI timeout.                      *)
(*                                                                        *)
(* 2 principals + depth 3 + 4 tokens is sufficient because:              *)
(*   - D1 (monotonic depth) is pairwise parent-child                     *)
(*   - D3 (temporal monotonicity) is pairwise parent-child               *)
(*   - D5 (terminal isolation) needs depth 0 reachable (depth 3 -> 0)    *)
(*   - DL1 (chain termination) needs at least one full chain             *)
(**************************************************************************)
EXTENDS CapabilityDelegation

const_Principals == {"alice", "bob"}

const_MaxDepth == 3

const_MaxTokens == 4

const_TimeValues == {1, 2, 3}

(* Bound the tokens set cardinality to keep state space finite.           *)
(* Without this, TLC explores all subsets of possible token combinations. *)
StateConstraint == Cardinality(tokens) <= 4

=========================================================================
