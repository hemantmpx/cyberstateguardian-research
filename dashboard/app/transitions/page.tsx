"use client";

import {
  Activity, AlertTriangle, ArrowDownUp, CheckCircle2, Clock3, Database,
  RefreshCw, ShieldCheck, Waypoints, XCircle
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
type Host = { host_id: string; hostname: string; os: string; architecture: string };
type MonitorHealth = {
  status: string; capture_method: string; observed_at: string; coverage_start?: string;
  coverage_end?: string; baseline_established: boolean; message?: string; metrics?: Record<string, unknown>;
};
type TransitionStatus = {
  enabled: boolean; enabled_categories: string[];
  categories: Record<string, { enabled: boolean; monitor_health?: MonitorHealth | null }>;
};
type Transition = {
  transition_id: string; host_id: string; category: string; object_key: string;
  transition_type: string; observed_at: string; window_start?: string; window_end?: string;
  old_state?: Record<string, unknown> | null; new_state?: Record<string, unknown> | null;
  changed_fields: string[]; capture_method: string; collector_health: string;
  raw_metadata: Record<string, unknown>;
};
type Reconciliation = { status: string; matched_evidence_ids: string[]; finalized: boolean; version: number };
type TimelineItem = { transition: Transition; latest_reconciliation?: Reconciliation | null };
type Trajectory = {
  trajectory_id: string; category: string; object_key: string; trajectory_type: string;
  interval: { start: string; end: string }; state_before?: { attributes: Record<string, unknown> } | null;
  state_after?: { attributes: Record<string, unknown> } | null;
  snapshot_delta?: { delta_type: string } | null;
  transitions: Transition[]; transition_links: { transition_id: string; relation: string }[];
  coverage_status: string; coverage_gaps: string[];
};

export default function TransitionsPage() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostId, setHostId] = useState("");
  const [category, setCategory] = useState("");
  const [objectInput, setObjectInput] = useState("");
  const [objectFilter, setObjectFilter] = useState("");
  const [windowHours, setWindowHours] = useState(24);
  const [status, setStatus] = useState<TransitionStatus | null>(null);
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [trajectories, setTrajectories] = useState<Trajectory[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reconciling, setReconciling] = useState("");

  const refresh = useCallback(async () => {
    if (!hostId) return;
    setLoading(true); setError(""); setNotice("");
    const end = new Date();
    const start = new Date(end.getTime() - windowHours * 60 * 60 * 1000);
    const query = new URLSearchParams({ start: start.toISOString(), end: end.toISOString() });
    if (category) query.set("category", category);
    if (objectFilter.trim()) query.set("object_key", objectFilter.trim());
    try {
      const [healthResponse, timelineResponse, trajectoryResponse] = await Promise.all([
        fetch(`${API}/api/transition-capture/status?host_id=${encodeURIComponent(hostId)}`, { cache: "no-store" }),
        fetch(`${API}/api/hosts/${encodeURIComponent(hostId)}/transition-timeline?${query}`, { cache: "no-store" }),
        fetch(`${API}/api/hosts/${encodeURIComponent(hostId)}/trajectories?${query}&limit=100`, { cache: "no-store" }),
      ]);
      if (!healthResponse.ok || !timelineResponse.ok || !trajectoryResponse.ok) {
        throw new Error("The transition API did not return a complete response. Check the CSG API and selected time range.");
      }
      const [healthData, timelineData, trajectoryData] = await Promise.all([
        healthResponse.json(), timelineResponse.json(), trajectoryResponse.json(),
      ]);
      setStatus(healthData as TransitionStatus);
      setTimeline((timelineData as TimelineItem[]).slice().reverse());
      setTrajectories((trajectoryData as Trajectory[]).slice().reverse());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load transition history.");
      setStatus(null); setTimeline([]); setTrajectories([]);
    } finally { setLoading(false); }
  }, [hostId, category, objectFilter, windowHours]);

  useEffect(() => {
    fetch(`${API}/api/hosts`, { cache: "no-store" }).then(async (response) => {
      if (!response.ok) throw new Error("Host list unavailable");
      const found = await response.json() as Host[];
      setHosts(found);
      if (found.length) setHostId(found[0].host_id);
    }).catch((reason) => setError(reason instanceof Error ? reason.message : "Could not load hosts."));
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);

  async function reconcile(transitionId: string) {
    setReconciling(transitionId); setNotice("");
    try {
      const response = await fetch(`${API}/api/transitions/${encodeURIComponent(transitionId)}/reconcile`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(String(body.detail || "Could not reconcile this transition."));
      setTimeline((rows) => rows.map((row) => row.transition.transition_id === transitionId
        ? { ...row, latest_reconciliation: body as Reconciliation } : row));
      setNotice(`Evidence check completed: ${String(body.status).replaceAll("_", " ").toLowerCase()}.`);
    } catch (reason) {
      setNotice(reason instanceof Error ? reason.message : "Evidence check failed.");
    } finally { setReconciling(""); }
  }

  const selectedHost = hosts.find((host) => host.host_id === hostId);
  return <main className="transition-app">
    <header className="transition-topbar">
      <a className="brand" href="/"><span className="brand-mark"><ShieldCheck size={20} /></span><span>CyberState<span>Guardian</span></span></a>
      <nav><a href="/">Control plane</a><a href="/results">Research results</a><a href="/ai-review">AI review</a><strong>State transitions</strong></nav>
    </header>
    <div className="transition-content">
      <section className="transition-title-row">
        <div><span className="section-eyebrow">CSG-NATIVE STATE OBSERVATIONS</span><h1>State transition history</h1><p>See what changed between authoritative snapshots, including temporary changes that returned to baseline.</p></div>
        <button className="secondary-button" onClick={() => void refresh()} disabled={loading}><RefreshCw size={15} className={loading ? "spin" : ""} /> Refresh</button>
      </section>

      <div className="transition-explainer"><Waypoints size={20} /><div><strong>Snapshots show the endpoints. Transition records show activity between them.</strong><p>A trajectory may have no net delta and still contain real intermediate changes. Wazuh corroboration is shown separately and never creates CSG state observations.</p></div></div>

      <section className="transition-controls" aria-label="Transition filters">
        <label>Windows host<select value={hostId} onChange={(event) => setHostId(event.target.value)}><option value="">Choose a host</option>{hosts.map((host) => <option key={host.host_id} value={host.host_id}>{host.hostname} · {host.host_id}</option>)}</select></label>
        <label>Time range<select value={windowHours} onChange={(event) => setWindowHours(Number(event.target.value))}><option value={6}>Last 6 hours</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option></select></label>
        <label>Category<select value={category} onChange={(event) => setCategory(event.target.value)}><option value="">All categories</option>{["service", "scheduled_task", "registry", "privileged_group", "process", "listener"].map((value) => <option key={value} value={value}>{label(value)}</option>)}</select></label>
        <label className="transition-object-filter">Object identity<input value={objectInput} onChange={(event) => setObjectInput(event.target.value)} placeholder="e.g. service:researchsvc" /></label>
        <button className="primary-button" onClick={() => { setObjectFilter(objectInput); if (objectFilter === objectInput) void refresh(); }} disabled={!hostId || loading}><Activity size={15} /> Apply</button>
      </section>

      {error && <div className="transition-message error"><XCircle size={17} />{error}</div>}
      {notice && <div className="transition-message"><CheckCircle2 size={17} />{notice}<button onClick={() => setNotice("")} aria-label="Dismiss"><XCircle size={15} /></button></div>}

      <section className="transition-section">
        <div className="transition-section-heading"><div><span className="section-eyebrow">MONITOR COVERAGE</span><h2>Is capture working?</h2><p>{selectedHost ? `${selectedHost.hostname} · ${selectedHost.os} · ${selectedHost.architecture}` : "Select the Windows lab host to inspect monitor health."}</p></div><span className={`capture-state ${status?.enabled ? "enabled" : "disabled"}`}>{status?.enabled ? "Capture enabled" : "Capture disabled"}</span></div>
        <div className="monitor-grid">{Object.entries(status?.categories || {}).map(([name, row]) => {
          const monitor = row.monitor_health;
          return <article className="monitor-row" key={name}><div className="monitor-name"><span className={`monitor-dot ${monitor?.status?.toLowerCase() || "unknown"}`} /><div><strong>{label(name)}</strong><small>{row.enabled ? "Enabled in CSG configuration" : "Disabled in CSG configuration"}</small></div></div><div className="monitor-value"><span>Health</span><strong>{monitor?.status || (row.enabled ? "No report" : "Off")}</strong></div><div className="monitor-value"><span>Capture method</span><strong>{monitor?.capture_method || "Not running"}</strong></div><div className="monitor-value"><span>Coverage baseline</span><strong>{monitor?.baseline_established ? formatTime(monitor.coverage_start) : "Not established"}</strong></div>{monitor?.message && <p className="monitor-message">{monitor.message}</p>}</article>;
        })}{!status && !error && <div className="transition-empty">Loading monitor health…</div>}</div>
        <p className="transition-caveat"><AlertTriangle size={15} />Category-scoped polling can miss changes shorter than its interval. Process start/exit uses Windows WMI indications. Health and coverage intervals are part of the evidence, not an assumption of uninterrupted capture.</p>
      </section>

      <section className="transition-section">
        <div className="transition-section-heading"><div><span className="section-eyebrow">SNAPSHOT INTERVAL ANALYSIS</span><h2>State trajectories</h2><p>Each row compares two direct-probe snapshots with any intermediate records in their interval.</p></div><span className="transition-count">{trajectories.length} trajectory{trajectories.length === 1 ? "" : "ies"}</span></div>
        <div className="trajectory-list">{trajectories.map((item) => <article className="trajectory-row" key={item.trajectory_id}>
          <div className="trajectory-heading"><div><span className={`trajectory-type ${item.trajectory_type.toLowerCase()}`}>{label(item.trajectory_type)}</span><strong>{item.category}</strong></div><span className={`health-label ${item.coverage_status.toLowerCase()}`}>Capture {label(item.coverage_status)}</span></div>
          <code className="transition-object-key">{item.object_key}</code>
          <div className="trajectory-states"><StateBlock label="Snapshot A" value={item.state_before?.attributes} /><ArrowDownUp size={17} /><StateBlock label="Snapshot B" value={item.state_after?.attributes} /><div className="net-delta"><span>Net delta</span><strong>{item.snapshot_delta?.delta_type || "None"}</strong></div></div>
          <div className="trajectory-transitions">{item.transitions.map((transition) => <div className="trajectory-event" key={transition.transition_id}><Clock3 size={14} /><time>{formatTime(transition.observed_at)}</time><strong>{label(transition.transition_type)}</strong><span>{transition.changed_fields.join(", ") || "object lifecycle"}</span><span className="capture-method">{transition.capture_method}</span></div>)}</div>
          {item.coverage_gaps.length > 0 && <div className="coverage-gap"><AlertTriangle size={14} />{item.coverage_gaps.join("; ")}</div>}
          <footer>Trajectory classification: <strong>{label(item.trajectory_type)}</strong> · {item.transition_links.length} transition link{item.transition_links.length === 1 ? "" : "s"}</footer>
        </article>)}{trajectories.length === 0 && <div className="transition-empty">No trajectory can be built for this range. At least two direct-probe snapshots are needed; intermediate records are listed below even when a boundary snapshot is missing.</div>}</div>
      </section>

      <section className="transition-section">
        <div className="transition-section-heading"><div><span className="section-eyebrow">PRIMARY CSG OBSERVATIONS</span><h2>Intermediate transition records</h2><p>Raw transition evidence is kept separate from snapshot deltas and Wazuh event evidence.</p></div><span className="transition-count">{timeline.length} record{timeline.length === 1 ? "" : "s"}</span></div>
        <div className="transition-record-list">{timeline.map(({ transition, latest_reconciliation: result }) => <article className="transition-record" key={transition.transition_id}>
          <div className="record-topline"><div><span className="record-category">{label(transition.category)}</span><span className="record-type">{label(transition.transition_type)}</span></div><time>{formatTime(transition.observed_at)}</time></div>
          <code className="transition-object-key">{transition.object_key}</code>
          <div className="record-state-grid"><StateBlock label="Before" value={transition.old_state} /><ArrowDownUp size={16} /><StateBlock label="After" value={transition.new_state} /></div>
          <div className="record-meta"><span>Changed fields <strong>{transition.changed_fields.join(", ") || "object appeared/disappeared"}</strong></span><span>Capture <strong>{transition.capture_method} · {transition.collector_health}</strong></span><span>Event-plane result <strong className={`reconcile-status ${(result?.status || "not_checked").toLowerCase()}`}>{result ? label(result.status) : "Not checked"}</strong></span></div>
          <div className="record-actions"><button className="secondary-button" disabled={Boolean(reconciling) || !status?.enabled_categories.includes(transition.category)} onClick={() => void reconcile(transition.transition_id)}>{reconciling === transition.transition_id ? <RefreshCw className="spin" size={14} /> : <RadioIcon />} Check Wazuh evidence</button>{result && <span>{result.matched_evidence_ids.length} matching evidence item{result.matched_evidence_ids.length === 1 ? "" : "s"} · review v{result.version}{result.finalized ? " · final" : " · pending"}</span>}</div>
        </article>)}{timeline.length === 0 && <div className="transition-empty">{loading ? "Loading transition records…" : "No intermediate transitions were recorded in this time range."}</div>}</div>
      </section>
      <footer className="transition-page-foot"><Database size={15} />Transitions are observations. Snapshot deltas, reconciliation decisions, authorization, findings, and risk remain separate CSG records.</footer>
    </div>
  </main>;
}

function StateBlock({ label: title, value }: { label: string; value?: Record<string, unknown> | null }) {
  return <div className="trajectory-state"><span>{title}</span><pre>{value ? JSON.stringify(value, null, 2) : "Absent"}</pre></div>;
}
function RadioIcon() { return <Activity size={14} />; }
function label(value: string) { return value.replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function formatTime(value?: string) { if (!value) return "Unknown"; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium" }).format(date); }
