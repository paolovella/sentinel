---- MODULE MC_NHICredentialRotation ----
(**************************************************************************)
(* Model checking configuration for NHICredentialRotation.                *)
(*                                                                        *)
(* Small model: 3 credentials, max time 6, sufficient to verify all      *)
(* rotation lifecycle properties including concurrent rotation and        *)
(* failure recovery paths.                                                *)
(**************************************************************************)
EXTENDS NHICredentialRotation, TLC

MC_CredIds == {"c1", "c2", "c3"}
MC_MaxTime == 6

=========================================================================
