---- MODULE MC_SequenceContainment ----
(**************************************************************************)
(* Model companion for SequenceContainment.tla                            *)
(* Provides concrete warmup/window constants for TLC model checking.      *)
(**************************************************************************)
EXTENDS SequenceContainment

const_WarmupCalls == 3
const_WindowMs == 1000
const_MaxNewTools == 2

=========================================================================
