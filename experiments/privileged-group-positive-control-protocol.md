# Privileged-Group Exact-Event Qualification Pilot

Protocol ID: `csg-privileged-group-positive-control-v1`  
Protocol status: frozen before the target membership mutation  
Study type: single-trial live qualification pilot, one Windows endpoint  
Ground truth: authorized benign lab administration; malicious intent is not tested

## Research purpose

Check whether the live Windows probe and Wazuh pipeline can independently observe one precisely
identified local Administrators membership addition, and whether CSG can reconcile only the event
for that exact member. This qualifies the privileged-group category before any repeated study; it
does not estimate reliability, detection efficacy, or a false-positive rate.

## Safe target behavior

Create one uniquely named local account with a randomly generated password and the account disabled.
Do not authenticate as that account. After establishing that it is absent from the local
Administrators group, add it to the group once. Capture the transition and its evidence, then remove
the membership and delete the account in a `finally` cleanup path. Do not change the Windows audit
policy; the preflight must show successful Security Group Management auditing already enabled.

## Frozen observations and decision rules

Before the action, require all of the following:

- Wazuh agent and Windows `WazuhSvc` are running.
- CSG API and Wazuh event/index providers are healthy.
- CSG privileged-group transition capture is enabled and reports `HEALTHY` with an established
  baseline for `win11-arm-lab`.
- Windows `Security Group Management` success auditing is enabled.
- The target user is disabled and is not a member of local `Administrators`.
- Record Windows build, probe package version, probe settings SHA-256, protocol SHA-256, and UTC
  action/query times. Never write the probe token or generated password into the result artifact.

The target transition is a pass only if the captured record is for the exact key
`privileged_group:administrators:<lowercase-host>/<lowercase-user>`, has type
`PRIVILEGED_MEMBER_ADDED`, and its new state includes the same member. The local Security event must
be Event ID 4732 and match the exact target member SID and local Administrators group. The Wazuh
record must be a non-synthetic `privileged_group_member_added` event for the same host and exact
object key. Reconciliation must report `CORROBORATED` and cite that Wazuh event ID; event type or
time proximity alone is insufficient.

If any exact identity check fails, retain the artifacts as a failed/inconclusive qualification pilot.
Do not relax matching rules after seeing the result. Diagnose the mismatch and create a new versioned
protocol before a repeat.

## Evidence and cleanup

The per-run JSON stores protocol/source/config hashes; preflight state and monitor health; the
assigned benign action and timestamps; target key, username, and SID; before/after membership
observations; the exact local Event 4732 record and XML; provider-returned Wazuh candidates; CSG
transition and reconciliation response; validation gates; and cleanup result. Output must not
contain credentials. Hash the run artifact after cleanup.

Cleanup always attempts, independently, to remove the target from Administrators and delete the
temporary account. Verify the account is absent, the group membership is absent, the Wazuh agent
and probe remain healthy, and the privileged-group monitor remains healthy. Cleanup failure marks
the pilot failed and requires operator attention; it is never silently counted as a pass.

## Interpretation boundary

One successful run is a category positive control only. It establishes neither repeated reliability
nor attack detection. The action is authorized and benign even though privileged-group addition is
a security-relevant behavior. A later repeated study must be separately frozen, include complete,
target-event-absent with a different-member distractor, and no-target-change with a distractor
conditions, preserve assignment/failure records, and use trial-level local/Wazuh identity audits.
