---- MODULE MC_IntentScopeContainment ----
(**************************************************************************)
(* Model companion for IntentScopeContainment.tla                         *)
(* Provides concrete sink class sets for TLC model checking.              *)
(**************************************************************************)
EXTENDS IntentScopeContainment

const_SinkClasses == {"ReadOnly", "FilesystemWrite", "NetworkEgress", "CodeExecution"}
const_AllowedSinks == {"ReadOnly", "FilesystemWrite", "NetworkEgress", "CodeExecution"}
const_TrustRanks == [t \in {"Low", "Medium", "High", "Verified"} |-> 0]

=========================================================================
