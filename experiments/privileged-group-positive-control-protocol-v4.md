# Privileged-Group Exact-Event Qualification Pilot, Version 4

Protocol ID: `csg-privileged-group-positive-control-v4`  
Protocol status: frozen before target membership mutation  
Study type: single-trial live qualification pilot on one Windows endpoint  
Ground truth: authorized benign lab administration; malicious intent is not tested

## Why Version 4

Versions 1 and 2 are retained as failed pilots. Version 3 captured the exact local 4732 event and
native-probe transition; deterministic reconciliation later cited the Wazuh event with the same
member SID and local EventRecordID. However, the runner's 90-second Wazuh polling window ended just
before that event became queryable. The automated run therefore failed its exact-event collection
gate even though a post-hoc query confirmed the exact event. That single observation is not a
latency distribution or a P95 estimate.

Version 4 keeps the exact host, event-code, group, member-SID, local-record-ID, and reconciliation
gates. It increases the predeclared Wazuh wait to 180 seconds to accommodate the observed
approximately 102-to-107-second event-time-to-index-availability bound, with headroom. This is an
operational wait limit based on a pilot observation, not a statistically calibrated service-level
objective. A new random member SID prevents earlier trials from satisfying the gate.

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
4. Within the frozen 180-second polling limit, the Wazuh provider returns a non-synthetic
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

One pass is only a positive-control qualification on one host and one behavior. The 180-second
wait is not a latency percentile. It is not a
randomized experiment, an attack, a maliciousness label, an efficacy estimate, or evidence of
cross-host reliability. A later repeated study must have its own preregistered assignments and
include complete exact evidence, target-event-absent with a different-member distractor, and
no-target-change with a distractor conditions.
