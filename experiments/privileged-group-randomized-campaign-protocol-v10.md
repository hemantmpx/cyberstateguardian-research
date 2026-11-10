# Privileged-Group Exact-Identity Reconciliation Campaign v10

Protocol ID: `csg-privileged-group-randomized-v10`  
Study type: prospective, randomized-within-block, one-endpoint live mechanism study  
Endpoint: `win11-arm-lab`  
Assigned sample: 10 blocks x 3 conditions = 30 trials  
Ground truth: controlled benign local-account/group administration; no attack is executed or labeled.

## Research question

When CSG observes an exact persistent local Administrators membership change, does deterministic
reconciliation require the matching Windows/Wazuh member identity rather than accepting any
same-host, same-event-type group event? Does the direct state plane preserve the observed change
when Windows does not emit the corresponding success-audit event, and does a wrong-member event
remain insufficient? This is a single-host mechanism study, not malicious-activity efficacy.

## Randomized conditions

Each block contains one randomly ordered trial from each condition. Every trial uses fresh,
uniquely named disabled local accounts and fresh SIDs. The target account is never used to log in.

1. `complete_with_distractor`: add both target and distractor accounts to `Administrators` with
   Security Group Management success auditing enabled. Both 4732 events must be locally recorded
   and visible to Wazuh. The target transition must reconcile as `CORROBORATED` using only the
   target SID's event; the distractor event must not be cited for it.
2. `target_audit_omission_with_distractor`: temporarily disable only Security Group Management
   success auditing for the target membership action, restore the exact preflight policy, then add
   the distractor with auditing enabled. The target state transition must still be observed; the
   target 4732 must be absent locally and from the Wazuh query; the wrong-member 4732 must be
   present; target reconciliation must be `UNEXPLAINED_BY_EVENT_PLANE` with no matched evidence.
   This models an endpoint audit-coverage omission, not Wazuh packet loss or permanent event loss.
3. `no_target_change_with_distractor`: leave the target account outside `Administrators`, add only
   the distractor with auditing enabled, and require no target membership state or target
   transition. The distractor must be observed and may reconcile for its own identity.

The two event-generating accounts are added back-to-back, with a maximum five-second action-start
gap. The captured local event timestamps and exact CSG transition windows are archived. Temporal
matching uses the transition's recorded `window_start`/`window_end` expanded by the predeclared
20-second event-time tolerance. A trial whose distractor falls outside the target transition's
expanded window is retained and marked a failed/inconclusive gate, not silently dropped.

## Frozen execution and evidence

Before the first mutation, freeze the protocol, randomized schedule, controller, Windows runner,
and independent analyzer by SHA-256. Each slot records the assignment, source code hashes, Windows
version/architecture, probe settings hash, Wazuh/API health, baseline audit policy, pre/post direct
probe snapshots, transition records, local Security XML for only the two test SIDs, normalized
Wazuh rows for only those SIDs, rows resolving the reconciliation's cited evidence IDs,
reconciliation revisions, cleanup, and postflight health.
Credentials, generated passwords, and bearer tokens must never be written into artifacts.

The Windows runner must restore the original audit success/failure values in a `finally` block,
even when event capture, API access, or assertions fail. It must refuse to run unless the baseline
policy is exactly the protocol's expected success-auditing state. It must remove group memberships
and delete both temporary accounts, then run one explicit read-only probe collection using the
installed probe configuration and confirm a fresh direct-probe snapshot excludes both identities.
The refresh exit code, timestamps, and resulting snapshot ID/time are archived. The controller
stops on any safety/cleanup failure and preserves partial data without assigning a passing result.
The explicit post-cleanup full-state probe uses a 30-second HTTP request timeout for that one-shot
process only. Because the probe is initialized from an explicit JSON file, the runner creates a
short-lived temporary copy with only `CSG_PROBE_TIMEOUT_SECONDS` changed, then deletes it in a
`finally` block. It records the effective timeout and temporary-file removal, and verifies the
installed settings-file hash is identical before and after. This addresses the large inventory
payload exceeding the general five-second default during calibration. If the one-shot still fails,
the slot fails cleanup and the campaign stops; a later periodic snapshot alone is not sufficient
to pass cleanup.

## Primary outcomes and predeclared gates

- State observation: exact target transition and target object presence in the two change arms;
  target absence and no target transition in the no-change arm.
- Event identity: exact host/agent, Security channel, provider, event code 4732, group
  `Administrators`, member SID, and equality of Wazuh and local Windows EventRecordID. Wazuh alert
  and archive indexes may represent the same Windows event with different CSG document IDs. The
  runner therefore resolves the reconciliation's cited IDs to provider rows and verifies the
  canonical Windows identity tuple; document-ID equality to an earlier alert/archive copy is not
  required.
- Reconciliation: exact-only `CORROBORATED` in the complete arm; no target evidence cited and
  `UNEXPLAINED_BY_EVENT_PLANE` in the audit-omission arm; no target transition/finding in the
  no-change arm.
- Distractor control: same group and event class, different member SID. Every cited target row
  must resolve to the target's local Windows EventRecordID/SID, and every distractor citation must
  resolve to the distractor's distinct EventRecordID/SID.
- Trial hygiene: local/Wazuh event-query coverage recorded; policy restored to exact baseline;
  both users and memberships removed; clean post-action direct-probe snapshot; monitor and Wazuh
  healthy.

Report assigned and valid denominators separately. Report all aborted/failed trials and reasons;
do not replace assignments or rerun until a result passes. Descriptive per-condition counts are
primary. Repeated trials on one VM are not independent endpoint samples. Do not report them as
cross-host generalization, attack detection accuracy, permanent telemetry loss, or superiority to
Wazuh.

## Stop conditions

Abort before a mutation if the probe, Wazuh agent/indexer, audit baseline, or SSH session is
unhealthy; stop the campaign immediately if audit restoration or cleanup fails. Preserve the raw
bundle and recover the VM before continuing. Do not change the expected outcomes after inspecting
trial results.
