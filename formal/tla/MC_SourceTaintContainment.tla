---- MODULE MC_SourceTaintContainment ----
(**************************************************************************)
(* Model companion for SourceTaintContainment.tla                         *)
(* Provides concrete tool/sink sets for TLC model checking.               *)
(**************************************************************************)
EXTENDS SourceTaintContainment

const_Tools == {"web_search", "file_read", "code_exec"}
const_UntrustedTools == {"web_search"}
const_VerifiedTools == {"code_exec"}
const_SinkClasses == {"ReadOnly", "FilesystemWrite", "NetworkEgress", "CodeExecution", "PolicyMutation"}
const_TrustRanks == [t \in {"Quarantined", "Untrusted", "Low", "Medium", "High", "Verified"} |-> 0]

=========================================================================
