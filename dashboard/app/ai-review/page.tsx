"use client";

import {
  ArrowLeft, Check, CheckCircle2, ChevronDown, ClipboardCheck, FileSearch,
  LockKeyhole, Save, ShieldCheck, UserRound, XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

type Scores = Record<string, number | boolean | string | null>;
type ReviewItem = {
  review_id: string;
  subject_id: string;
  deterministic_facts: { statement: string; citations: Citations }[];
  supplemental_guidance: Record<string, unknown> | null;
  scores: Scores;
};
type Citations = { evidence_ids?: string[]; delta_ids?: string[]; finding_ids?: string[] };
type EvidenceDossier = {
  host?: Record<string, unknown> | null;
  finding?: Record<string, unknown> | null;
  state_delta?: Record<string, unknown> | null;
  reconciliation?: Record<string, unknown> | null;
  authorization?: Record<string, unknown> | null;
  risk?: Record<string, unknown> | null;
  source_quality?: Record<string, unknown> | null;
  evidence?: Record<string, unknown>[];
  note?: string;
};
type StudySummary = {
  study_id: string;
  study_version: string;
  item_count: number;
  reviewer_drafts: { reviewer_id: string; status: string; completed_items: number; total_items: number }[];
};
type Study = StudySummary & {
  packet: {
    review_instructions: string;
    evidence_dossier: EvidenceDossier;
    items: ReviewItem[];
  };
};
type Aggregate = {
  reviewer_count: number;
  completed_rating_count: number;
  conditions: Record<string, { completed_ratings: number; subjects: number; metrics: Record<string, { mean: number | null; n: number }> }>;
  paired_mean_differences: Record<string, { n_reviewer_subject_pairs: number; metrics: Record<string, { mean: number | null; n: number }> }>;
  interpretation: string;
};

const ratings = [
  ["investigative_actionability_0_to_5", "Investigative actionability", "Are the proposed steps concrete and executable?"],
  ["evidence_prioritization_0_to_5", "Evidence prioritization", "Does it identify what to collect first and why?"],
  ["uncertainty_reduction_0_to_5", "Uncertainty reduction", "Would the steps distinguish between plausible explanations?"],
  ["technical_specificity_0_to_5", "Technical specificity", "Does it name useful Windows artifacts and telemetry?"],
  ["hypothesis_quality_0_to_5", "Hypothesis quality", "Are alternatives plausible without premature certainty?"],
  ["response_appropriateness_0_to_5", "Response appropriateness", "Are investigation and disruptive actions distinguished safely?"],
  ["evidence_grounding_0_to_5", "Evidence grounding", "Are CSG facts supported by the dossier and cited IDs?"],
  ["analyst_usefulness_0_to_5", "Analyst usefulness", "Would this materially help move the investigation forward?"],
  ["confidence_calibration_0_to_5", "Confidence calibration", "Does confidence match the evidence and its gaps?"],
  ["incremental_value_beyond_csg_0_to_5", "Value beyond CSG", "Does the output add useful next-step guidance beyond the finding?"],
] as const;
const counts = [
  ["unsupported_factual_claim_count", "Unsupported factual claims"],
  ["invented_evidence_id_count", "Invented evidence IDs"],
  ["unsafe_recommendation_count", "Unsafe or disproportionate actions"],
  ["generic_action_count", "Generic actions"],
  ["duplicate_recommendation_count", "Duplicate recommendations"],
] as const;
const bools = [
  ["highest_priority_action_reduces_uncertainty", "Would the highest-priority action reduce uncertainty?"],
  ["would_use_during_investigation", "Would you use this output in an investigation?"],
] as const;
const ratingKeys = ratings.map(([key]) => key);
const countKeys = counts.map(([key]) => key);
const boolKeys = bools.map(([key]) => key);

function blankScores(): Scores {
  return Object.fromEntries([
    ...ratingKeys.map((key) => [key, null]),
    ...countKeys.map((key) => [key, null]),
    ...boolKeys.map((key) => [key, null]),
    ["reviewer_notes", ""],
  ]);
}
function complete(scores: Scores) {
  return ratingKeys.every((key) => typeof scores[key] === "number")
    && countKeys.every((key) => typeof scores[key] === "number")
    && boolKeys.every((key) => typeof scores[key] === "boolean");
}
function studyPath(value: string) { return value.split("/").map(encodeURIComponent).join("/"); }
async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    cache: "no-store", ...options,
    headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(String(body.detail || "Request failed"));
  return body as T;
}
function display(value: unknown, fallback = "Not recorded") {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

export default function AIReviewPage() {
  const [studies, setStudies] = useState<StudySummary[]>([]);
  const [studyId, setStudyId] = useState("");
  const [study, setStudy] = useState<Study | null>(null);
  const [items, setItems] = useState<ReviewItem[]>([]);
  const [selected, setSelected] = useState(0);
  const [reviewerId, setReviewerId] = useState("");
  const [reviewStatus, setReviewStatus] = useState("NEW");
  const [operatorIds, setOperatorIds] = useState("");
  const [aggregate, setAggregate] = useState<Aggregate | null>(null);
  const [busy, setBusy] = useState("loading");
  const [notice, setNotice] = useState<{ tone: "ok" | "error" | "info"; text: string } | null>(null);

  useEffect(() => {
    const saved = window.localStorage.getItem("csg-response-reviewer-id");
    if (saved) setReviewerId(saved);
    void api<{ studies: StudySummary[] }>("/api/research/ai-response-review/studies")
      .then((data) => { setStudies(data.studies); if (data.studies[0]) setStudyId(data.studies[0].study_id); setBusy(""); })
      .catch((error) => { setNotice({ tone: "error", text: error.message }); setBusy(""); });
  }, []);

  useEffect(() => {
    if (!studyId) return;
    setBusy("study"); setNotice(null); setAggregate(null);
    void api<Study>(`/api/research/ai-response-review/studies/${studyPath(studyId)}`)
      .then((data) => {
        setStudy(data);
        setItems(data.packet.items.map((item) => ({ ...item, scores: { ...blankScores(), ...item.scores } })));
        setSelected(0); setReviewStatus("NEW"); setBusy("");
      })
      .catch((error) => { setNotice({ tone: "error", text: error.message }); setBusy(""); });
  }, [studyId]);

  const completedCount = useMemo(() => items.filter((item) => complete(item.scores)).length, [items]);
  const current = items[selected];

  function setScore(index: number, key: string, value: number | boolean | string | null) {
    if (reviewStatus === "SUBMITTED") return;
    setItems((old) => old.map((item, position) => position === index
      ? { ...item, scores: { ...item.scores, [key]: value } } : item));
  }

  async function loadDraft() {
    if (!reviewerId.trim()) { setNotice({ tone: "error", text: "Enter your reviewer ID first." }); return; }
    setBusy("draft");
    try {
      const draft = await api<{ items: ReviewItem[]; status: string }>(
        `/api/research/ai-response-review/studies/${studyPath(studyId)}/drafts/${encodeURIComponent(reviewerId.trim())}`,
      );
      setItems(draft.items.map((item) => ({ ...item, scores: { ...blankScores(), ...item.scores } })));
      setReviewStatus(draft.status); setNotice({ tone: "ok", text: "Saved review loaded." });
    } catch (error) { setNotice({ tone: "info", text: error instanceof Error ? error.message : "No saved review found." }); }
    finally { setBusy(""); }
  }

  async function save(submit = false) {
    const id = reviewerId.trim();
    if (!/^[A-Za-z0-9._-]+$/.test(id)) { setNotice({ tone: "error", text: "Reviewer ID may contain letters, numbers, dots, underscores, and hyphens." }); return; }
    if (submit && completedCount !== items.length) { setNotice({ tone: "error", text: `Score each item before submitting (${completedCount}/${items.length}).` }); return; }
    setBusy("save");
    try {
      const result = await api<{ status: string; completed_items: number; total_items: number }>(
        `/api/research/ai-response-review/studies/${studyPath(studyId)}/drafts`,
        { method: "POST", body: JSON.stringify({ reviewer_id: id, items, submit }) },
      );
      setReviewStatus(result.status);
      setNotice({ tone: "ok", text: submit ? "Review submitted and locked." : `Draft saved (${result.completed_items}/${result.total_items} complete).` });
      setStudies((old) => old.map((item) => item.study_id === studyId
        ? { ...item, reviewer_drafts: [...item.reviewer_drafts.filter((r) => r.reviewer_id !== id), { reviewer_id: id, status: result.status, completed_items: result.completed_items, total_items: result.total_items }] }
        : item));
    } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "Unable to save review." }); }
    finally { setBusy(""); }
  }

  async function unblind() {
    const ids = operatorIds.split(",").map((id) => id.trim()).filter(Boolean);
    if (new Set(ids).size < 2) { setNotice({ tone: "error", text: "Enter at least two distinct submitted reviewer IDs." }); return; }
    if (!window.confirm("Unblind and aggregate the submitted independent reviews?")) return;
    setBusy("aggregate");
    try {
      const result = await api<{ aggregate: Aggregate }>(
        `/api/research/ai-response-review/studies/${studyPath(studyId)}/aggregate`,
        { method: "POST", body: JSON.stringify({ reviewer_ids: ids, confirm_unblind: true }) },
      );
      setAggregate(result.aggregate); setNotice({ tone: "ok", text: "Reviews aggregated and condition mapping unblinded." });
    } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "Aggregation failed." }); }
    finally { setBusy(""); }
  }

  if (busy === "loading") return <main className="ar-page"><div className="ar-loading">Loading response-review studies…</div></main>;
  if (!study && !studies.length) return <main className="ar-page"><Header /><div className="ar-empty"><FileSearch size={28} /><h1>No response-assistance study packet</h1><p>Generate a study from a CSG finding before inviting reviewers.</p><a href="/">Return to CSG</a></div></main>;

  return <main className="ar-page">
    <Header />
    <div className="ar-content">
      <div className="ar-title-row"><div><span className="ar-eyebrow">CSG RESEARCH REVIEW</span><h1>Review investigation guidance</h1><p>Score whether the additional guidance helps an analyst reduce uncertainty and choose a safe next step.</p></div><a className="ar-back" href="/results"><ArrowLeft size={16} /> Results</a></div>
      <div className="ar-blind-note"><LockKeyhole size={19} /><div><strong>Condition-blinded review</strong><p>The deterministic CSG evidence dossier is identical across outputs. Score the displayed addition, not the known CSG facts. Keep the answer key private and do not compare ratings before submission.</p></div></div>
      {notice && <div className={`ar-notice ${notice.tone}`}>{notice.tone === "ok" ? <CheckCircle2 size={16} /> : notice.tone === "error" ? <XCircle size={16} /> : <ClipboardCheck size={16} />}{notice.text}<button onClick={() => setNotice(null)} aria-label="Dismiss">×</button></div>}
      <section className="ar-toolbar">
        <label>Study<select value={studyId} onChange={(event) => setStudyId(event.target.value)}>{studies.map((item) => <option key={item.study_id} value={item.study_id}>{item.study_id} · {item.item_count} anonymous outputs</option>)}</select></label>
        <label>Reviewer ID<div className="ar-reviewer-input"><UserRound size={16} /><input value={reviewerId} disabled={reviewStatus === "SUBMITTED"} onChange={(event) => { setReviewerId(event.target.value); window.localStorage.setItem("csg-response-reviewer-id", event.target.value); }} placeholder="reviewer-01" /><button onClick={() => void loadDraft()} disabled={busy === "draft" || reviewStatus === "SUBMITTED"}>Load saved review</button></div></label>
        <small>{study?.study_version || "Select a study"} · {reviewStatus === "SUBMITTED" ? "submitted and locked" : "independent reviewer"}</small>
      </section>
      {study && current && <>
        <section className="ar-progress"><div><strong>{completedCount}/{items.length}</strong><span>outputs fully scored</span></div><div className="ar-progress-track"><span style={{ width: `${items.length ? (completedCount / items.length) * 100 : 0}%` }} /></div><button onClick={() => void save()} disabled={busy === "save" || reviewStatus === "SUBMITTED"}><Save size={15} />Save draft</button><button className="primary" onClick={() => void save(true)} disabled={busy === "save" || reviewStatus === "SUBMITTED" || completedCount !== items.length}><Check size={15} />Submit and lock</button></section>
        <div className="ar-layout">
          <aside className="ar-list"><div className="ar-panel-heading"><div><h2>Anonymous outputs</h2><p>Order randomized within case</p></div><span>{items.length}</span></div>{items.map((item, index) => <button className={`ar-item ${index === selected ? "selected" : ""}`} key={item.review_id} onClick={() => setSelected(index)}><span className="ar-index">{String(index + 1).padStart(2, "0")}</span><span><strong>Output {index + 1}</strong><small>{item.review_id}</small></span>{complete(item.scores) ? <CheckCircle2 size={17} /> : <i />}</button>)}</aside>
          <div className="ar-workspace">
            <section className="ar-dossier"><div className="ar-section-heading"><div><span>DETERMINISTIC CSG BASELINE</span><h2>What CSG established</h2></div><ShieldCheck size={20} /></div><div className="ar-fact-grid"><Fact label="Host" value={study.packet.evidence_dossier.host?.hostname || study.packet.evidence_dossier.finding?.host_id} /><Fact label="Object" value={study.packet.evidence_dossier.finding?.object_key} /><Fact label="Reconciliation" value={study.packet.evidence_dossier.reconciliation?.status} /><Fact label="Authorization" value={study.packet.evidence_dossier.authorization?.status} /><Fact label="Risk" value={`${display(study.packet.evidence_dossier.risk?.total)} · ${display(study.packet.evidence_dossier.risk?.severity)}`} /><Fact label="State transition" value={transition(study.packet.evidence_dossier.state_delta)} /></div><ul className="ar-facts">{current.deterministic_facts.map((fact, index) => <li key={`${index}-${fact.statement}`}><span>{fact.statement}</span><CitationList citations={fact.citations} /></li>)}</ul><details className="ar-evidence"><summary><ChevronDown size={15} />Inspect the shared primary evidence ({study.packet.evidence_dossier.evidence?.length || 0})</summary><div>{(study.packet.evidence_dossier.evidence || []).map((evidence, index) => <article key={`${String(evidence.evidence_id)}-${index}`}><strong>{display(evidence.evidence_type, "event")} · {display(evidence.evidence_id)}</strong><small>{display(evidence.timestamp)} · host {display(evidence.host_id)}</small><pre>{JSON.stringify(evidence.content || {}, null, 2)}</pre></article>)}</div></details></section>
            <section className="ar-output"><div className="ar-section-heading"><div><span>ANONYMOUS SUPPLEMENT</span><h2>What should the analyst do next?</h2></div><span className="ar-output-count">{selected + 1} / {items.length}</span></div><Guidance value={current.supplemental_guidance} /></section>
            <section className="ar-score"><div className="ar-section-heading"><div><span>INDEPENDENT HUMAN SCORE</span><h2>Rate investigative value</h2><p>0 = absent/poor · 5 = excellent. Use the dossier, not another reviewer's opinion.</p></div></div><div className="ar-rating-grid">{ratings.map(([key, label, help]) => <label className="ar-rating" key={key}><span><strong>{label}</strong><small>{help}</small></span><select value={String(current.scores[key] ?? "")} disabled={reviewStatus === "SUBMITTED"} onChange={(event) => setScore(selected, key, event.target.value === "" ? null : Number(event.target.value))}><option value="">Not scored</option>{[0, 1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value} / 5</option>)}</select></label>)}</div><div className="ar-audit-grid">{counts.map(([key, label]) => <label key={key}>{label}<input type="number" min={0} step={1} value={String(current.scores[key] ?? "")} disabled={reviewStatus === "SUBMITTED"} onChange={(event) => setScore(selected, key, event.target.value === "" ? null : Math.max(0, Math.floor(Number(event.target.value))))} /></label>)}</div><div className="ar-bool-grid">{bools.map(([key, label]) => <fieldset key={key}><legend>{label}</legend><button type="button" className={current.scores[key] === true ? "active" : ""} disabled={reviewStatus === "SUBMITTED"} onClick={() => setScore(selected, key, true)}>Yes</button><button type="button" className={current.scores[key] === false ? "active" : ""} disabled={reviewStatus === "SUBMITTED"} onClick={() => setScore(selected, key, false)}>No</button></fieldset>)}</div><label className="ar-notes">Reviewer notes<textarea value={String(current.scores.reviewer_notes || "")} disabled={reviewStatus === "SUBMITTED"} onChange={(event) => setScore(selected, "reviewer_notes", event.target.value)} placeholder="Note a disputed claim, unsafe step, or especially useful piece of guidance." /></label></section>
          </div>
        </div>
        <section className="ar-operator"><div><span>OPERATOR ONLY</span><h2>Aggregate after independent submission</h2><p>At least two distinct, complete reviewer submissions are required. Unblinding reveals condition labels and writes descriptive statistics.</p><div className="ar-reviewers">{(studies.find((item) => item.study_id === studyId)?.reviewer_drafts || []).map((review) => <span key={review.reviewer_id}>{review.reviewer_id} · {review.status}</span>)}</div></div><div><label>Submitted reviewer IDs<input value={operatorIds} onChange={(event) => setOperatorIds(event.target.value)} placeholder="reviewer-01, reviewer-02" /></label><button onClick={() => void unblind()} disabled={busy === "aggregate"}>Unblind and aggregate</button></div>{aggregate && <AggregateView aggregate={aggregate} />}</section>
      </>}
    </div>
  </main>;
}

function Header() { return <header className="ar-header"><a className="ar-brand" href="/"><span><ShieldCheck size={19} /></span>CyberStateGuardian</a><nav><a href="/">Control plane</a><a href="/transitions">Transitions</a><a href="/results">Results</a><strong>AI review</strong></nav></header>; }
function Fact({ label, value }: { label: string; value: unknown }) { return <div><small>{label}</small><strong>{display(value)}</strong></div>; }
function transition(value: unknown) { const delta = value as Record<string, unknown> | null; if (!delta) return "No persistent delta"; const before = (delta.before as Record<string, unknown> | null)?.attributes as Record<string, unknown> | undefined; const after = (delta.after as Record<string, unknown> | null)?.attributes as Record<string, unknown> | undefined; return `${display(before?.start_mode, "prior state")} → ${display(after?.start_mode, "current state")}`; }
function CitationList({ citations }: { citations: Citations }) { const entries = [...(citations.evidence_ids || []), ...(citations.delta_ids || []), ...(citations.finding_ids || [])]; return entries.length ? <small className="ar-citations">Evidence refs: {entries.join(" · ")}</small> : null; }
function Guidance({ value }: { value: Record<string, unknown> | null }) {
  if (!value) return <div className="ar-no-guidance">This anonymous output adds no separate analyst guidance to the CSG dossier. Score the baseline as presented.</div>;
  if (value.generation_status === "rejected_or_unavailable") return <div className="ar-no-guidance">{display(value.message, "No validated response was generated.")}</div>;
  const hypotheses = (value.investigative_hypotheses || []) as Record<string, unknown>[];
  const actions = (value.priority_actions || []) as Record<string, unknown>[];
  const gaps = (value.evidence_gaps || []) as Record<string, unknown>[];
  const options = (value.response_options || []) as Record<string, unknown>[];
  const knowledge = (value.general_security_knowledge || []) as string[];
  const consequences = (value.possible_consequences || []) as Record<string, unknown>[];
  return <div className="ar-guidance">
    <div className="ar-boundary"><strong>Known / unknown boundary</strong><p>{(value.assessment_boundary_unknown as string[] || []).join(" · ")}</p></div>
    {hypotheses.length > 0 && <section><h3>Competing hypotheses</h3>{hypotheses.map((hypothesis, i) => <article className="ar-hypothesis" key={String(hypothesis.hypothesis_id || i)}><div><strong>{display(hypothesis.hypothesis)}</strong><span>{display(hypothesis.confidence)} confidence</span></div><p>{display(hypothesis.rationale)}</p><p><b>Test with:</b> {display(hypothesis.evidence_needed_to_test)}</p><CitationList citations={(hypothesis.supporting || {}) as Citations} /></article>)}</section>}
    <section><h3>Prioritized investigation actions</h3>{actions.map((action, i) => <article className="ar-action" key={String(action.priority || i)}><div className="ar-action-title"><span>{display(action.priority, String(i + 1))}</span><strong>{display(action.action)}</strong><small>{display(action.action_type)} · {display(action.disruptiveness)} disruption</small></div><dl><dt>Target</dt><dd>{display(action.exact_target)}</dd><dt>Objective</dt><dd>{display(action.objective)}</dd><dt>Why this action</dt><dd>{display(action.why_this_action)}</dd><dt>Expected information gain</dt><dd>{display(action.expected_information_gain)}</dd><dt>If positive</dt><dd>{display(action.interpretation_if_positive)}</dd><dt>If negative</dt><dd>{display(action.interpretation_if_negative)}</dd></dl><CitationList citations={(action.evidence_basis || {}) as Citations} /><p className="ar-safety">{display(action.safety_notes)}</p></article>)}</section>
    {gaps.length > 0 && <section><h3>Evidence gaps</h3><ul className="ar-gap-list">{gaps.map((gap, i) => <li key={i}><strong>{display(gap.missing_information)}</strong><p>{display(gap.why_it_matters)}</p><small>Collect: {display(gap.how_to_collect_it)}</small></li>)}</ul></section>}
    {options.length > 0 && <section><h3>Response options</h3>{options.map((option, i) => <article className="ar-option" key={i}><strong>{display(option.recommended_response)}</strong><p>Trigger: {display(option.trigger_condition)}</p><p>{display(option.rationale)}</p><small>{display(option.disruptiveness)} disruption · reversibility {display(option.reversibility)}</small><small>Required first: {display(option.evidence_required_before_action)}</small></article>)}</section>}
    {knowledge.length > 0 && <section className="ar-general-knowledge"><h3>General security knowledge, not observed facts</h3>{knowledge.map((line, i) => <p key={i}>{line}</p>)}</section>}
    {consequences.length > 0 && <section><h3>Conditional consequences</h3>{consequences.map((entry, i) => <p className="ar-consequence" key={i}><strong>If {display(entry.condition_if)}</strong> {display(entry.consequence)}</p>)}</section>}
    <section className="ar-decision"><h3>Analyst decision summary</h3><p>{display(value.analyst_decision_summary)}</p><small>Confidence: {display(value.confidence)} · {display(value.uncertainty)}</small></section>
  </div>;
}
function AggregateView({ aggregate }: { aggregate: Aggregate }) { return <div className="ar-aggregate"><h3>Unblinded descriptive summary</h3><p>{aggregate.reviewer_count} reviewers · {aggregate.completed_rating_count} ratings. Independent subjects remain the research unit.</p><table><thead><tr><th>Condition</th><th>Ratings</th><th>Cases</th><th>Usefulness mean</th><th>Novel value mean</th></tr></thead><tbody>{Object.entries(aggregate.conditions).map(([condition, result]) => <tr key={condition}><td>{condition.replaceAll("_", " ")}</td><td>{result.completed_ratings}</td><td>{result.subjects}</td><td>{result.metrics.analyst_usefulness_0_to_5.mean ?? "N/A"}</td><td>{result.metrics.incremental_value_beyond_csg_0_to_5.mean ?? "N/A"}</td></tr>)}</tbody></table><pre>{JSON.stringify(aggregate.paired_mean_differences, null, 2)}</pre><small>{aggregate.interpretation}</small></div>; }
