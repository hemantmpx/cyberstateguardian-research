# WFP 5154 Randomized Listener Reconciliation Campaign

**Study:** `listener-wfp5154-randomized-three-arm-v1`  
**Design:** prospective, randomized within-host mechanism study; 10 blocks x 3 conditions (30 assigned trials).  
**Endpoint:** `win11-arm-lab`, one Windows 11 ARM64 VM.  
**Status:** freeze this protocol and schedule before any assigned mutation.

## Question

When CSG's native probe detects a new TCP listener, can exact reconciliation distinguish the
target's own Windows Filtering Platform (WFP) Event 5154 from an event for a different port? Does
the probe retain state-change visibility when WFP auditing is disabled during the target action?

## Assigned Arms

Each randomized block contains one trial from each arm. Ports are unique across all 30 slots.

| Arm | Action | Expected target outcome |
|---|---|---|
| `complete_exact` | Temporarily enable WFP Connection Success auditing. Emit a short wrong-port distractor, then hold the target loopback listener. | Local and Wazuh Event 5154 identify both ports. CSG observes target ADD and finalizes `CONSISTENT`, citing only the exact target event. |
| `target_event_absent_with_distractor` | Emit the distractor under temporary WFP auditing, restore `No Auditing`, then hold the target listener with auditing off. | Probe sees target ADD; no target local/Wazuh 5154; complete query contains the exact distractor; target finalizes `UNEXPLAINED`, with no citations. |
| `no_change_with_distractor` | Emit the distractor under temporary WFP auditing, restore `No Auditing`, and leave the target port untouched during the observation period. | No target listener, event, delta, or finding; complete query contains the distractor. |

## Collection And Decision Rules

- Target identity is `listener:tcp:127.0.0.1:<assigned-port>`.
- A qualifying Wazuh event must be normalized as `listener_created` and have the exact target key.
- Local Windows and Wazuh physical identity must agree on agent, Security channel, EventID 5154,
  and EventRecordID. Alert/archive aliases are not independent OS events.
- Same-host, wrong-port events are distractors and must never support the target finding.
- The target-event-absent arm is specifically a **WFP audit-policy omission at the endpoint**. It
  is not permanent loss, an agent outage, or a claim that Wazuh lost an event Windows emitted.
- Event queries use a five-second pre-action margin and a fixed 60-second post-action grace. The
  final complete observation is ingested once into CSG; query-attempt summaries and full final
  provider results are retained.
- The probe's listener category must be healthy. Missing event data is not called `UNEXPLAINED` if
  the event query is incomplete or any required source is degraded or unavailable.
- Do not replace assigned trials. Retain action, capture, source, API, and cleanup failures.

## Safety And Cleanup

Listeners bind only to loopback and use randomized high ports. The Windows runner requires Wazuh and
the CSG probe task running, and the WFP audit baseline to be `No Auditing`. It enables Success
auditing only for assigned phases, restores the baseline in `finally`, and verifies both ports are
closed. No service, account, scheduled task, firewall, or persistent configuration is changed.
Stop if audit restoration, socket cleanup, or endpoint health fails.

## Analysis And Claim Boundary

Independently audit every trial's raw Windows record, provider result, CSG state delta/finding, exact
physical event joins, source/query health, and cleanup. Report assigned/evaluable counts and all
gate failures. Keep the three arms separate; intervals, if shown, are descriptive for a single
endpoint. The trial is benign listener behavior and tests this WFP event class only. It does not
test malicious intent, attack-detection efficacy, permanent/natural telemetry loss, product-wide
Wazuh performance, or between-host generalization. It does not replace a labeled security-behavior
study or second-host replication.
