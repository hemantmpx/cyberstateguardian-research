# Privileged-Group Exact-Event Qualification Pilot, Version 6

Protocol ID: `csg-privileged-group-positive-control-v6`  
Protocol status: frozen before target membership mutation  
Study type: single-trial live qualification pilot on one Windows endpoint  
Ground truth: authorized benign lab administration; malicious intent is not tested

## Why Version 6

Versions 1 through 5 are retained with their original artifacts and excluded from any prospective
qualified denominator. Versions 2 through 5 created and cleaned up benign test accounts. CSG
reconciliation cited exact Wazuh Event 4732 records for v2 through v5, matching the local Windows
record ID and the transition's group/member SID. However, the runners' polling check was defective:
they piped the API function call directly into PowerShell `Where-Object`. In Windows PowerShell,
the returned event array was treated as a single pipeline object, so the persisted candidate was
the entire event list rather than individually filtered events. A post-run test that first assigned
the API response to a variable and then filtered its rows returned the exact target event.

Therefore the v2-v5 runner-level exact-event polling booleans and candidate counts are invalid.
They cannot establish event absence, delivery latency, or a polling timeout. The successful
reconciliation records remain valid evidence that CSG's server-side matcher correlated the exact
event during its own query, but they do not repair the runner's failed qualification gates.

Version 6 explicitly assigns the API response before enumerating and filtering individual event
rows. It keeps the exact host, event-code, group, SID, local-record-ID, and reconciliation gates.
The 300-second wait is only an operational cap; no latency conclusion is drawn from previous runs.
A fresh random SID prevents earlier events from satisfying this run.

## Research purpose

Qualify the live privileged-group evidence path before any repeated campaign: can the Windows probe
observe one exact local Administrators membership addition, can Wazuh provide the corresponding
Security Event 4732 for the same account, and does deterministic CSG reconciliation accept only
that exact group/member identity? The primary identity is the Windows member SID, with a member
name accepted only when present and exact. This pilot does not estimate reliability, detection
efficacy, or a false-positive rate.

## Safe target behavior

Create one uniquely named local account with a random password and the account disabled. Never
authenticate as the account. Verify it is not in local `Administrators`, then add it once. Do not
change Windows audit policy. After capture and reconciliation, remove the membership and delete
the account in a `finally` cleanup path. Verify Windows shows the target membership and account
absent. Poll the continuously running direct-probe snapshot endpoint until a snapshot built after
cleanup confirms the target is absent; do not issue a large one-shot inventory request during
cleanup. Do not store the generated password or probe bearer token.

## Source and environment freeze

Before the target action, a separate JSON freeze manifest must bind the exact runner SHA-256 and
protocol SHA-256. The runner refuses to act if either digest differs. Every run archives exact
copies of the runner, protocol, and freeze manifest and records those digests, the probe-settings
digest, Windows build/architecture, probe Python and Wazuh agent versions, preflight health, audit
policy, action/query timestamps, raw evidence, validation, and cleanup.

## Preconditions

- Elevated Windows session; Windows Wazuh service running; Wazuh endpoint agent active.
- CSG Wazuh API/indexer status healthy.
- CSG privileged-group transition capture enabled and `HEALTHY` with baseline established for
  `win11-arm-lab`.
- Windows `Security Group Management` success auditing already enabled. No policy change is made.
- Unique disabled target account absent from the Administrators group.
- A direct-probe snapshot before the action confirms the target object is absent.

## Frozen pass criteria

All of these must pass for this one trial to qualify the category:

1. Windows verifies the target membership was added exactly once.
2. CSG captures transition type `PRIVILEGED_MEMBER_ADDED` for exact key
   `privileged_group:administrators:<lowercase-host>/<lowercase-user>`.
3. A local Security Event ID 4732 exists after the action and its `MemberSid` is the exact test
   account SID while `TargetUserName` is `Administrators`.
4. Within the frozen 300-second polling limit, the Wazuh provider returns a non-synthetic
   `privileged_group_member_added` event for the same
   host, event code 4732, exact group name, and exact member SID. Its Windows event record ID must
   equal the locally captured Security record ID. A member name or CSG target key is not required
   when the exact SID is present.
5. CSG reconciliation is `CORROBORATED` and cites that exact Wazuh event ID.
6. Cleanup removes group membership, deletes the disabled account, and a fresh direct-probe
   snapshot no longer contains the target key; the monitor remains healthy.

An event type or time match without exact member SID/group identity is a failure. A candidate for a
different SID or group is a distractor and must not corroborate the transition. If any criterion
fails, retain the result as failed/inconclusive, diagnose without changing the pass criteria, and
freeze a new protocol before another target mutation.

## Safety, storage, and claim limits

The temporary account is disabled, randomly named, and never used to log in. Cleanup runs regardless
of validation success. The per-run folder is unique and overwrite is refused. Store the raw local
event XML and normalized Wazuh candidates necessary to audit identity; do not export unrelated
Security log contents or credentials. Hash every run artifact with a portable LF checksum catalog.

One pass is only a positive-control qualification on one host and one behavior. The 300-second
wait is not a latency percentile. It is not a randomized experiment, an attack, a maliciousness
label, an efficacy estimate, or evidence of
cross-host reliability. A later repeated study must have its own preregistered assignments and
include complete exact evidence, target-event-absent with a different-member distractor, and
no-target-change with a distractor conditions.
