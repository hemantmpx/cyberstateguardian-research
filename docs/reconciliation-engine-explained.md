# CyberStateGuardian Reconciliation Engine

## Purpose

This document explains how CyberStateGuardian (CSG) reconciles persistent host-state
observations from the native CSG probe with transient event telemetry from Wazuh.

It is aligned with the current implementation. Reconciliation is deterministic and
object-specific. AI is not authoritative for the reconciliation result. AI receives an
evidence package after the deterministic pipeline has produced its result.

## The Research Idea

CSG observes two related but different evidence planes:

    Persistent state plane                 Event plane
    ----------------------                 ----------------
    Native CSG probe                       Windows events / Sysmon
    Services, tasks, registry,             Wazuh agent and indexer
    listeners, processes                   Normalized transient events
              |                                      |
              v                                      v
        StateSnapshot                         NormalizedEvent
              |                                      |
              +------------------+-------------------+
                                 v
                          Reconciliation
                                 |
                                 v
                 Finding, risk, authorization, incident
                                 |
                                 v
                      Evidence-grounded AI analysis

The research question is:

> When CSG independently observes a persistent state transition, does the event plane
> contain the matching event for the same host, object, operation, and transition within
> the declared time boundary?

This distinguishes:

1. A state change and its exact event are both visible.
2. The state change is visible but the event is delayed or missing.
3. A related event exists, but it does not prove the exact state transition.

## Key Terms

### State snapshot

A StateSnapshot is a timestamped representation of what the native probe observed on one
host. It contains normalized StateObject records and category-collection health.

Example objects:

    service:csgresearch123
    scheduled_task:\\updates\\check
    registry:hklm/software/microsoft/windows/currentversion/run/updater
    listener:tcp:0.0.0.0:8443

The object key is intended to be stable across snapshots. It is the identity used to
decide whether the same object exists in both observations.

### Normalized event

A NormalizedEvent is a provider-independent event representation. Wazuh fields are mapped
to a normalized event type, host, time, target, actor, and attributes.

Examples include service_created, service_modified, scheduled_task_created,
registry_value_modified, and process_start.

### State delta

A StateDelta is the difference between two snapshots. It records:

- host;
- category and stable object key;
- ADD, REMOVE, or MODIFY;
- the before object, when available;
- the after object, when available;
- source-quality information;
- the interval during which the transition occurred;
- experiment and trial scope, when present.

### Reconciliation

Reconciliation is the deterministic comparison of one state delta against candidate
normalized events. It produces a ReconciliationResult containing status, matched event IDs,
missing expected event types, reasons, confidence, time window, and audit metadata.

### Finding

A finding is the security-research record created from a state delta. It combines the
reconciliation result with authorization and deterministic risk scoring. A finding is not
synonymous with a confirmed attack.

## Stage 1: State Snapshots

The native probe collects Windows state and normalizes each category into stable objects.
It also reports whether collection was usable.

Example:

    Snapshot S1 at 10:00:00
      service:csgresearch123 = absent

    Snapshot S2 at 10:00:05
      service:csgresearch123 = present
        service_name = CSGResearch123
        start_mode   = manual
        account      = LocalSystem

Category health matters. If the service collector was unusable in either snapshot, CSG
does not treat the absence or presence as a reliable delta. This prevents a broken
collector from being interpreted as a real deletion or creation.

The authoritative research configuration uses the native probe for the state plane and
Wazuh for the event plane. Wazuh inventory can still be used for cross-validation, but it
is not the independent state observation in that configuration.

## Stage 2: Computing State Deltas

The DeltaEngine verifies that both snapshots belong to the same host and state source.
It groups objects by category and compares the union of their stable keys.

For each key:

    previous missing, current present          ADD
    previous present, current missing          REMOVE
    both present, normalized attributes differ MODIFY
    otherwise                                  no delta

Attribute comparison uses category-aware normalization. Formatting differences that do
not represent a meaningful state change should not create a MODIFY delta.

The delta observation interval is:

    delta.observation_window.start = previous.built_at
    delta.observation_window.end   = current.built_at

CSG normally cannot know the exact second when a change occurred. It knows that the change
happened between two observations. The reconciliation window is therefore derived from
this interval instead of pretending that the later snapshot timestamp is the exact action
time.

Source-quality metadata is carried into the delta so later risk and interpretation can
distinguish a reliable observation from a degraded one.

Implementation: backend/csg/state/diff.py.

## Stage 3: Expected Evidence

The reconciliation engine maps each delta category and operation to expected event types.

| State delta | Required primary event | Accepted related event | Meaning |
| --- | --- | --- | --- |
| Service ADD | service_created | process_start | Service installation is required for full corroboration. |
| Service MODIFY | service_modified | process_start | The service transition must also agree. |
| Scheduled task ADD | scheduled_task_created | process_start | A process alone does not prove task creation. |
| Scheduled task MODIFY | scheduled_task_modified | process_start | The task modification event is primary. |
| Registry change | registry_value_modified | process_start | Registry identity must match. |
| Privileged-group change | privileged_group_member_added | process_start | Group and member must match. |
| Listener ADD | listener_created | network_activity, process_start | A connection is not proof of a local listener. |
| Process ADD | process_start | none | Process creation is the primary event. |

The primary event is required for CONSISTENT. A related event can provide context but is
weaker and produces PARTIALLY_EXPLAINED when no primary event is available.

For Windows privileged-group additions (including Security Event 4732), reconciliation requires
the normalized group and the exact member identity. When Windows provides a member SID, CSG uses
that SID as the identity key; it does not substitute the event's actor, a missing member name, or
another account in the group. A local EventRecordID is useful to audit that Wazuh forwarded the
same Windows record, but it supplements rather than replaces the group/member identity check. The
October 16 v6 qualification pilot exercised this path end to end; it is one benign trial, not a
reliability estimate. Its evidence and the correction to earlier runner polling are in the
[pilot dossier](../experiments/results/runs/20261016/privileged-group-positive-control-pilot-v6/RESULTS.md).

## Stage 4: Event Window

CSG uses the measured transition interval plus event-time tolerance. The current default
tolerance is five seconds:

    accepted event window =
        [previous snapshot time - 5 seconds,
         current snapshot time + 5 seconds]

The distinction between tolerance and grace is important:

    event-time tolerance = how far an event timestamp may be from the transition interval
    grace period         = how long CSG waits for late event delivery before finalizing

The historical 900-second observation setting remains for compatibility with old records
and callers. New deltas use their actual snapshot interval plus tolerance.

## Stage 5: Exact Matching

An event is accepted only when the applicable checks pass:

    host(event)       == host(delta)
    event.type        in expected primary or related types
    event.time        inside delta window plus tolerance
    object identity   matches delta object
    transition        is compatible with before/after state

In shorthand:

    Match(e, d) =
      Host(e) = Host(d)
      AND Type(e) in ExpectedTypes(d)
      AND Time(e) in Window(d)
      AND Identity(e) = Identity(d)
      AND Transition(e) ~= Transition(d)

### Service identity

For a service delta, CSG prefers the internal service name, not the display name.

    delta: service:csgresearch123
    event: service_name = CSGResearch123

This does not match:

    delta: service:csgresearch123
    event: service_name = CSGResearch999

The event type, host, and minute can match and the event still remains invalid for this
delta. This prevents an old event from a different service trial being reused as evidence.

### Other identities

- Scheduled tasks require the normalized task name.
- Registry paths are normalized for case and separator differences.
- Privileged-group events require both group and member.
- Listener events require matching local port and protocol.
- Process ADD requires a matching process-start event.

### Service transition identity

For a service MODIFY, CSG compares before and after startup modes. Windows terminology
such as demand start is normalized to the same meaning as manual.

Accepted:

    CSG state:   manual -> automatic
    Wazuh event: demand -> auto

Rejected:

    CSG state:   manual -> automatic
    Wazuh event: disabled -> manual

When object and operation appear related but before/after values conflict, CSG records a
transition mismatch and does not accept that event as proof.

## Stage 6: Base Result

The basic engine behaves as follows:

    if any primary event matches:
        status = CONSISTENT
        confidence = 0.95
    elif any related event matches:
        status = PARTIALLY_EXPLAINED
        confidence = 0.65
    else:
        status = UNEXPLAINED
        confidence = 0.35

These confidence values are fixed engineering heuristics. They are not model probabilities,
attack probabilities, or accuracy measurements.

The result records:

- matched event IDs;
- one reason per matched event;
- missing primary event types;
- the exact observation window;
- transition mismatches;
- the deterministic rule name;
- event-plane health metadata, when available.

For a removal delta, the current research scope returns NOT_APPLICABLE. Removal semantics
are excluded from primary success rates until category-specific expected removal evidence is
defined.

## Stage 7: Latency-Aware Lifecycle

The base result is a point-in-time evaluation. The lifecycle layer makes it suitable for
live telemetry, where events can arrive after the state probe.

The finalization deadline is:

    event window end + reconciliation grace period

Normal sequence:

    delta created
        |
        v
    initial event query
        |
        +-- exact primary event found ------> CONSISTENT, finalized
        |
        +-- no event and collection pending -> PENDING_EVIDENCE
                                                 |
                                                 v
                                      re-evaluate when events arrive
                                                 |
                                     exact event found -> CONSISTENT
                                     deadline closes  -> UNEXPLAINED

The lifecycle distinguishes event-source health:

| Situation | Semantic interpretation |
| --- | --- |
| Exact primary event found | CORROBORATED |
| No event, query complete, source healthy | UNCORROBORATED_HEALTHY |
| No event, endpoint/transport/index degraded | UNCORROBORATED_DEGRADED |
| Same object/type but incompatible transition | CONTRADICTED metadata |
| Evidence opportunity still open | INCONCLUSIVE metadata and usually PENDING_EVIDENCE |

These semantic labels are stored in result metadata. The primary enum status remains the
lifecycle status such as PENDING_EVIDENCE, CONSISTENT, or UNEXPLAINED.

Health attribution is tied to the transition's observation interval, not simply to the latest poll.
If a later poll has no health result, the lifecycle can retain a previous known observation only
when its recorded check time falls inside that exact interval. A current in-window observation
takes precedence. The result records whether health came from the current poll or a prior in-window
observation, together with the observation itself. This prevents a later out-of-window `UNKNOWN`
from erasing a relevant health fact; it does not turn an absent event into proof that every event
class was configured or collected. A live ten-trial verification is documented in the [v61
follow-up report](../experiments/results/published/2026-10-14-v61-health-attribution-followup.md).

An unexplained result is not created merely because one query returned zero rows. CSG waits
for the declared boundary unless the result is already corroborated.

## Late Events and Versioned History

When a worker cycle or provider synchronization receives new events, CSG re-evaluates
pending findings and event-time windows that overlap the new evidence.

A material change creates a new revision instead of overwriting history:

    version 1: PENDING_EVIDENCE
    version 2: UNEXPLAINED
    version 3: CONSISTENT

Each revision records its predecessor through supersedes_reconciliation_id. The finding
points to the latest result, while the repository retains the complete history.

This lets a researcher audit what CSG knew at every point in time.

## Live Pipeline

The live pipeline performs:

1. Store the new state snapshot.
2. Compare it with the previous snapshot.
3. Persist new deltas.
4. Retrieve events in each delta window.
5. Create normalized evidence records.
6. Evaluate reconciliation lifecycle status.
7. Evaluate authorization independently.
8. Calculate deterministic risk.
9. Persist the finding and reconciliation revision.
10. Assign the finding to an incident when appropriate.

When state_provider is probe, synchronization reuses the latest native-probe snapshot and
queries Wazuh for the event plane. Event observations include collection and retrieval
health so a missing event is not over-interpreted.

Implementation locations:

- backend/csg/services/live_pipeline.py
- backend/csg/services/provider_sync.py
- backend/csg/services/reconciliation.py
- backend/csg/services/reconciliation_lifecycle.py

## Worked Example: Correct Service Match

State observations:

    10:00:00  Snapshot A: service X absent
    10:00:05  Snapshot B: service X present

CSG creates:

    ADD service:service_x

Wazuh contains:

    event type:  service_created
    service:     service_x
    host:        win11-arm-lab
    event time:  10:00:04

Host, type, identity, and time match.

    status:  CONSISTENT
    semantic: CORROBORATED
    matched_evidence_ids: [exact Wazuh event ID]

## Worked Example: Wrong-Object Distractor

CSG observes service_x. Wazuh contains service_y on the same host in the same minute.

The type and host match, but identity does not.

After the lifecycle closes:

    status: UNEXPLAINED
    semantic: UNCORROBORATED_HEALTHY
    matched_evidence_ids: []
    missing_expected_evidence_types: [service_created]

This is the key distractor experiment. It demonstrates that CSG is not searching for any
same-type event in a broad time window.

## Worked Example: Delayed Event

    10:00:05  CSG detects service X
    10:00:06  initial Wazuh query: no event
    10:00:06  result: PENDING_EVIDENCE
    10:00:09  exact service X event arrives
    10:00:10  re-evaluation: CONSISTENT

The pending result is retained, but the latest finding points to the corroborated revision.

## Worked Example: Capture Drop

    10:00:05  CSG detects service X
    10:00:05  Wazuh agent is stopped
    10:00:06  query completes but endpoint collection is unavailable
    deadline   no exact event arrives

The state-plane finding remains visible:

    status:  UNEXPLAINED
    semantic: UNCORROBORATED_DEGRADED

This demonstrates retained visibility under event-source degradation. It does not prove
that the event would have been absent if Wazuh had remained healthy.

## Separate Decisions

These questions are intentionally separate:

    Did the state change happen?       state delta
    Did Wazuh corroborate it?          reconciliation
    Was it approved?                   authorization
    How should it be prioritized?      deterministic risk
    Which findings belong together?    incident correlation
    What might the sequence mean?      AI interpretation

For example:

    reconciliation: CONSISTENT
    authorization:  UNKNOWN
    risk:            MEDIUM

A matching event proves telemetry agreement. It does not prove authorization or benign
intent. An UNEXPLAINED result similarly does not prove maliciousness.

## AI Boundary

The AI service receives an evidence package after deterministic processing. The package can
contain the finding, delta, before/after state, event timeline, authorization, risk,
incident context, and source-health information.

AI may:

- summarize what changed;
- explain the temporal sequence;
- rank evidence already in the package;
- suggest candidate ATT&CK techniques;
- identify uncertainty and missing evidence;
- recommend investigation steps.

AI must not:

- change reconciliation status;
- invent or authorize a state change;
- treat a related event as an exact match;
- modify deterministic risk evidence;
- declare attacker intent without primary evidence;
- use its previous interpretation as new evidence;
- delete findings or execute remediation.

Safe architecture:

    deterministic reconciliation
                |
                v
         evidence package
                |
                v
    AI interpretation and evidence ranking
                |
                v
          optional human review

If AI-assisted reconciliation is studied later, it should be treated as assistance for
ambiguous evidence association. Its proposed relationship must be stored separately from
the authoritative result and validated against the actual package IDs, host, object, type,
and time.

## What Reconciliation Proves

Under the declared collection and timing assumptions, CSG can establish that:

- a persistent state transition was observed by the native probe;
- an exact event was or was not present in the queried evidence;
- the event matched the same host and object identity;
- the event described a compatible operation and transition;
- event collection was healthy, degraded, unavailable, or incomplete;
- the result changed as delayed evidence arrived.

## What It Does Not Prove

CSG does not establish:

- that a state change was malicious;
- that a user was unauthorized because no approval was found;
- that Wazuh never collected an event outside the declared window;
- that both sensors are independent if both are compromised;
- that a healthy query proves every event class was configured;
- that the fixed confidence value is a probability;
- that AI interpretation is ground truth.

The threat model excludes a fully compromised host that can manipulate both collection paths.

## Research Experiment Matrix

| Condition | State plane | Event plane | Expected result |
| --- | --- | --- | --- |
| Complete | change observed | exact event present | CONSISTENT |
| Delayed | change observed | exact event arrives later | PENDING then CONSISTENT |
| Capture drop | change observed | source unavailable | final UNEXPLAINED, degraded |
| Healthy missing | change observed | source healthy, exact event absent | final UNEXPLAINED, healthy |
| Distractor | change A observed | event for object B | UNEXPLAINED |
| No change | no state delta | irrelevant events | no finding |
| Approved change | change observed | exact event present | corroborated and authorized |

Required trial artifacts include:

- before and after snapshots;
- delta and observation interval;
- raw normalized event attributes;
- matched and rejected event IDs;
- source-health evidence;
- reconciliation versions;
- authorization decision;
- risk components;
- experiment and trial scope;
- cleanup evidence.

Useful metrics include state-plane recall, event availability, exact-object match accuracy,
false CONSISTENT rate, false UNEXPLAINED rate, retained visibility during event loss,
and P50/P95/P99 detection and reconciliation latency.

## Code Traceability

| Responsibility | Implementation |
| --- | --- |
| Snapshot comparison | backend/csg/state/diff.py |
| Expected event rules and exact matching | backend/csg/services/reconciliation.py |
| Pending/final/revised lifecycle | backend/csg/services/reconciliation.py and reconciliation_lifecycle.py |
| Live finding creation | backend/csg/services/live_pipeline.py |
| Wazuh event retrieval and health | backend/csg/services/provider_sync.py and providers/wazuh.py |
| Risk scoring | backend/csg/services/risk.py |
| AI interpretation boundary | backend/csg/services/llm_analysis.py |
| Domain models | backend/csg/domain/models.py |
| Reconciliation tests | tests/unit/test_reconciliation.py and tests/unit/test_reconciliation_lifecycle.py |

## Final Interpretation

CSG is not simply asking whether Wazuh has an alert. It compares an independently
observed persistent state transition with a narrowly bounded, identity-specific event
assertion while preserving source health and timing uncertainty.

The distinction is:

    Wazuh event only:
        An event was reported.

    CSG dual-plane reconciliation:
        The endpoint state changed in this specific way, and the event plane did or did not
        provide matching evidence for that exact transition under known collection conditions.

AI can make the evidence easier to understand, but the auditable state transition and
reconciliation decision remain in the deterministic CSG pipeline.

## Continuous Transition Records Are A Separate Evidence Layer

The optional probe transition-capture feature adds a record between snapshots without replacing a
snapshot or its delta. The relationship is:

```text
Snapshot A ---- existing DeltaEngine ---- Snapshot B
    \                                  /
     \--- ordered StateTransitionRecords
                    |
                    +-- StateTrajectoryBuilder checks boundary and chain continuity
                    +-- TransitionReconciliationService checks Wazuh event evidence
```

The records and the existing delta have different jobs. A delta says how the endpoint's compared
persistent state differs between snapshots. A transition record says what a category monitor saw
happen to one exact object between samples, including the observed old/new data and the monitor's
capture method/health. A trajectory uses the two snapshot boundaries to validate whether the chain
is complete and how it relates to net state. Transition records do not independently create findings.

For example, if a service begins in Manual mode, changes to Automatic, then returns to Manual before
Snapshot B, the ordinary state delta is empty. If both object-specific transitions are captured and
their old/new states form a continuous chain, the trajectory is `REVERTED`. If only the runtime
`status` field changed and that field is intentionally excluded from the persistent snapshot delta,
the trajectory is `NON_PERSISTENT_TRANSITION`, not `REVERTED`. A broken chain is `INCONSISTENT`;
absence of records is a `TRANSITION_CAPTURE_GAP` only when a snapshot delta exists, otherwise
coverage health determines whether the interval is stable or unobserved.

Transition-to-Wazuh reconciliation is a second independent query. The event must match the same
host and canonical object key, compatible normalized event type and operation, and the transition's
sampling interval plus configured tolerance. The result also retains whether query, endpoint,
transport, and index coverage were complete. Thus a healthy empty query can become
`UNEXPLAINED_BY_EVENT_PLANE`; an unavailable query remains `PENDING_EVIDENCE`; an exact match becomes
`CORROBORATED`. Version history allows late events to change the conclusion without rewriting the
original transition.

The full domain, transport, setup and live-experiment design are documented in
[Continuous State Transition Capture](continuous-state-transition-capture.md). The Windows-specific
runner checks the exact transition IDs and requires a trajectory whose snapshot IDs match the
requested pair; if an intervening periodic snapshot splits the interval, it does not call the run a
successful reversion trial.
