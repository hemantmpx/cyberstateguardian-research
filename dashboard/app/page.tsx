"use client";

import {
  Activity, Beaker, Check, ChevronRight, CircleAlert, ClipboardCheck, Clock3, Database, ExternalLink,
  FlaskConical, Gauge, GitBranch, Laptop, LoaderCircle, Play, RadioTower, RefreshCw,
  RotateCcw, ShieldCheck, SquareTerminal, Waypoints, X
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";

const API = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

type Host = { host_id: string; hostname: string; os: string; architecture: string };
type Health = { status: string; environment: string };
type Collector = { status: string };
type ProbeObservation = { host_id: string; observed_at: string; source: string; categories: Record<string, Collector> };
type Agent = { id: string; name?: string; ip?: string; status?: string; os?: string };
type WazuhStatus = {
  configured: boolean; ok: boolean; event_provider: string; dashboard_url: string;
  server_api: { ok: boolean }; indexer: { ok: boolean; cluster_name?: string };
  agent_count: number; endpoint_agent_count: number; agents: Agent[];
  sync: { lookback_seconds: number }; warnings: string[];
};
type Scenario = { scenario_id: string; description: string; classification: string; telemetry_condition: string; event_source_status: string; expected_reconciliation: string; ground_truth_notes: string };
type Finding = { finding_id: string; category: string; object_key?: string; authorization_status: string; reconciliation: { status: string }; risk: { total: number; severity: string } };
type Incident = { incident_id: string; title: string; status: string; finding_ids: string[] };
type Run = { run_id: string; scenario_id: string; ground_truth_classification: string; success: boolean; started_at: string; actual_observations: { delta_count?: number; event_count?: number } };
type ActionResponse = { action?: string; detail?: string; [key: string]: unknown };

async function get<T>(path: string, fallback: T): Promise<T> {
  try { const response = await fetch(`${API}${path}`, { cache: "no-store" }); return response.ok ? ((await response.json()) as T) : fallback; } catch { return fallback; }
}

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);
  const [wazuh, setWazuh] = useState<WazuhStatus | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [observations, setObservations] = useState<Record<string, ProbeObservation>>({});
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedScenario, setSelectedScenario] = useState("all");
  const [repetitions, setRepetitions] = useState(1);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  const refresh = useCallback(async () => {
    const [nextHealth, nextWazuh, nextHosts, nextScenarios, nextRuns, nextFindings, nextIncidents] = await Promise.all([
      get<Health | null>("/health", null), get<WazuhStatus | null>("/api/wazuh/status", null),
      get<Host[]>("/api/hosts", []), get<Scenario[]>("/api/experiments/scenarios", []),
      get<Run[]>("/api/experiments/runs?limit=12", []), get<Finding[]>("/api/findings?limit=8", []),
      get<Incident[]>("/api/incidents?limit=8", [])
    ]);
    setHealth(nextHealth); setWazuh(nextWazuh); setHosts(nextHosts); setScenarios(nextScenarios);
    setRuns(nextRuns); setFindings(nextFindings); setIncidents(nextIncidents);
    const current: Record<string, ProbeObservation> = {};
    await Promise.all(nextHosts.map(async (host) => { const item = await get<ProbeObservation | null>(`/api/hosts/${host.host_id}/observations/latest`, null); if (item) current[host.host_id] = item; }));
    setObservations(current);
  }, []);

  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 15000); return () => window.clearInterval(timer); }, [refresh]);

  async function execute(action: string, body: Record<string, unknown> = {}) {
    setBusy(action); setNotice(null);
    try {
      const response = await fetch(`${API}/api/experiments/actions`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action, ...body }) });
      const payload = (await response.json()) as ActionResponse;
      if (!response.ok) throw new Error(String(payload.detail || "Action failed"));
      setNotice({ kind: "ok", text: actionMessage(payload) }); await refresh();
    } catch (error) { setNotice({ kind: "error", text: error instanceof Error ? error.message : "Action failed" }); }
    finally { setBusy(null); }
  }

  const primaryHost = hosts[0];
  const observation = primaryHost ? observations[primaryHost.host_id] : undefined;
  const healthyCollectors = observation ? Object.values(observation.categories).filter((item) => item.status === "healthy").length : 0;
  const collectorCount = observation ? Object.keys(observation.categories).length : 0;
  const selected = scenarios.find((scenario) => scenario.scenario_id === selectedScenario);

  return <main className="app-shell">
    <aside className="rail">
      <a className="brand" href="#overview"><span className="brand-mark"><ShieldCheck size={20} /></span><span>CyberState<span>Guardian</span></span></a>
      <div className="rail-label">CSG research lab</div>
      <nav className="rail-nav">
        <a className="active" href="#overview"><Gauge size={17} /> Home</a>
        <a href="#experiment-lab"><FlaskConical size={17} /> Run a test</a>
        <a href="#integrations"><RadioTower size={17} /> Connections</a>
        <a href="#evidence"><Waypoints size={17} /> Findings</a>
        <a href="/transitions"><Activity size={17} /> Transitions</a>
        <a href="/ai-review"><ClipboardCheck size={17} /> AI review</a>
        <a href="/results"><Database size={17} /> Results <ChevronRight className="nav-arrow" size={14} /></a>
      </nav>
      <div className="rail-bottom"><div className="rail-meta">LAB VERSION</div><strong>v0.5.3</strong><span>Windows endpoint connected</span></div>
    </aside>

    <section className="main-column">
      <header className="topbar"><div className="breadcrumbs"><span>CSG</span><ChevronRight size={14} /><strong>Control plane</strong></div><div className="top-actions"><span className={`system-state ${health?.status === "ok" ? "online" : "offline"}`}><span className="state-dot" /> {health?.status === "ok" ? "API operational" : "API unavailable"}</span><button className="icon-button" onClick={() => void refresh()} title="Refresh all live data" aria-label="Refresh all live data"><RefreshCw size={17} /></button><a className="avatar" href="/results">H</a></div></header>
      <div className="content">
        <section id="overview" className="hero-row"><div><div className="eyebrow"><span className="live-pulse" /> CYBERSTATEGUARDIAN RESEARCH LAB</div><h1>Run a test. Understand what changed.</h1><p className="hero-copy">Use the Windows lab to change one thing, compare what CSG saw with what Wazuh reported, and review the result in plain language.</p></div><a className="results-cta" href="/results"><Database /><span><strong>Open research record</strong><small>Reports, evidence, and limitations</small></span><ChevronRight size={17} /></a></section>

        <section className="how-it-works" aria-label="How the lab works"><div className="how-intro"><span className="section-eyebrow">START HERE</span><h2>Three simple steps</h2><p>This lab tests whether persistent system changes remain visible when event telemetry is delayed or missing.</p></div><div className="step-card"><span>01</span><div><strong>Change something</strong><p>Create a controlled Windows service or run a labeled scenario.</p></div></div><div className="step-card"><span>02</span><div><strong>Compare the sources</strong><p>The CSG probe records system state. Wazuh supplies event history.</p></div></div><div className="step-card"><span>03</span><div><strong>Read the result</strong><p>CSG reports what changed, whether an event supports it, and what is still unknown.</p></div></div></section>

        <section className="status-grid" aria-label="System status"><StatusTile icon={<Activity size={18} />} label="CSG service" value={health?.status === "ok" ? "Ready" : "Unavailable"} detail={health?.environment || "Waiting for API"} tone={health?.status === "ok" ? "green" : "red"} /><StatusTile icon={<Laptop size={18} />} label="Windows probe" value={observation ? "Sending state" : "No recent state"} detail={primaryHost ? `${healthyCollectors}/${collectorCount || 0} checks healthy` : "Windows host not registered"} tone={observation ? "green" : "amber"} /><StatusTile icon={<RadioTower size={18} />} label="Wazuh events" value={wazuh?.ok ? "Connected" : "Check connection"} detail={wazuh ? `${wazuh.endpoint_agent_count} Windows agent${wazuh.endpoint_agent_count === 1 ? "" : "s"}` : "Status unavailable"} tone={wazuh?.ok ? "blue" : "amber"} /><StatusTile icon={<Database size={18} />} label="Test machine" value={primaryHost?.hostname || "Not registered"} detail={primaryHost ? `${primaryHost.os} · ${primaryHost.architecture}` : "win11-arm-lab pending"} tone="slate" /></section>
        {notice && <div className={`action-notice ${notice.kind}`}><span>{notice.kind === "ok" ? <Check size={16} /> : <CircleAlert size={16} />}</span>{notice.text}<button onClick={() => setNotice(null)} aria-label="Dismiss notification"><X size={15} /></button></div>}

        <section id="experiment-lab" className="section-block"><SectionHeading eyebrow="01 / RUN A TEST" title="Choose what to test" action={<span className="section-count"><Beaker size={15} /> {scenarios.length} tests available</span>} /><div className="lab-layout">
          <div className="lab-setup panel-surface"><div className="panel-heading"><div><h2>Test setup</h2><p>Pick one test for a focused result, or run the full set for a complete comparison.</p></div><span className="ready-tag"><span className="state-dot" /> Ready</span></div><label className="field-label" htmlFor="scenario">What should CSG test?</label><select id="scenario" value={selectedScenario} onChange={(event) => setSelectedScenario(event.target.value)}><option value="all">All tests · recommended for a baseline</option>{scenarios.map((scenario) => <option key={scenario.scenario_id} value={scenario.scenario_id}>{scenario.scenario_id}</option>)}</select>{selected ? <div className="scenario-preview"><div className="scenario-topline"><span className={`class-tag ${selected.classification}`}>{selected.classification}</span><span>{selected.telemetry_condition}</span></div><strong>{selected.description}</strong><p>{selected.ground_truth_notes}</p><div className="scenario-facts"><span>Expected result <b>{selected.expected_reconciliation}</b></span><span>Event source <b>{selected.event_source_status}</b></span></div></div> : <div className="scenario-preview suite"><div className="scenario-topline"><span className="class-tag suite-tag">FULL BASELINE</span><span>controlled tests</span></div><strong>Run every labeled test in the research suite.</strong><p>This covers normal changes, suspicious changes, and cases where Wazuh events are removed or unavailable.</p><div className="scenario-facts"><span>Tests <b>{scenarios.length || 7}</b></span><span>Saved as <b>separate run records</b></span></div></div>}<div className="run-controls"><label className="field-label" htmlFor="repetitions">Repeat this test</label><input id="repetitions" type="number" min={1} max={10} value={repetitions} onChange={(event) => setRepetitions(Math.min(10, Math.max(1, Number(event.target.value))))} /><button className="primary-button" disabled={Boolean(busy)} onClick={() => void execute("run_fixture_suite", { scenario_id: selectedScenario === "all" ? null : selectedScenario, repetitions })}><Play size={16} fill="currentColor" />{busy === "run_fixture_suite" ? "Running…" : "Start test"}</button></div></div>
          <div className="operations panel-surface"><div className="panel-heading"><div><h2>Run the live workflow</h2><p>Use these actions after a Windows change or when checking the lab.</p></div><SquareTerminal size={20} className="heading-icon" /></div><OperationRow icon={<RefreshCw size={17} />} title="Refresh Windows and Wazuh" detail="Collect the latest state and event records, then compare them." button="Refresh lab" busy={busy === "sync_host"} onClick={() => primaryHost && void execute("sync_host", { host_id: primaryHost.host_id })} disabled={!primaryHost} /><OperationRow icon={<RotateCcw size={17} />} title="Finish open results" detail="Recheck changes whose event window is still open." button="Finish results" busy={busy === "process_backlog"} onClick={() => void execute("process_backlog")} /><OperationRow icon={<GitBranch size={17} />} title="Group related findings" detail="Put related changes into one incident for easier review." button="Group findings" busy={busy === "correlate_backlog"} onClick={() => void execute("correlate_backlog")} /></div>
        </div></section>

        <section id="integrations" className="section-block"><SectionHeading eyebrow="02 / CONNECTIONS" title="Are both sources working?" action={wazuh?.dashboard_url ? <a className="text-link" href={wazuh.dashboard_url} target="_blank" rel="noreferrer">Open Wazuh <ExternalLink size={14} /></a> : undefined} /><div className="integration-grid"><IntegrationPanel title="CSG Windows probe" icon={<Laptop size={19} />} tone="green" rows={[["What it records", "Persistent system state"], ["Machine", primaryHost?.hostname || "win11-arm-lab"], ["Last check", observation ? formatTime(observation.observed_at) : "No observation"], ["Health checks", observation ? `${healthyCollectors} healthy / ${collectorCount} total` : "Waiting"]]} footer={observation ? "This is the independent state source used to detect changes." : "The Windows probe has not reported recently."} /><IntegrationPanel title="Wazuh" icon={<RadioTower size={19} />} tone="blue" rows={[["What it provides", "Security events"], ["Server API", wazuh?.server_api.ok ? "Reachable" : "Unavailable"], ["Indexer", wazuh?.indexer.ok ? (wazuh.indexer.cluster_name || "Reachable") : "Unavailable"], ["Windows agents", wazuh ? String(wazuh.endpoint_agent_count) : "Unknown"]]} footer={wazuh?.warnings[0] || "CSG uses these events to explain or question a state change."} /></div><div className="agent-strip"><div className="agent-strip-title"><span><RadioTower size={16} /> Wazuh agents seen by CSG</span><strong>{wazuh?.agent_count ?? 0}</strong></div><div className="agent-chips">{(wazuh?.agents || []).map((agent) => <span className={`agent-chip ${agent.status === "active" ? "active" : ""}`} key={agent.id || agent.name}><span className="state-dot" />{agent.name || agent.id}<small>{agent.status || "unknown"}</small></span>)}{!wazuh?.agents.length && <span className="muted-note">No Wazuh agents returned.</span>}</div></div></section>

        <section id="evidence" className="section-block"><SectionHeading eyebrow="03 / WHAT CHANGED" title="Recent findings" action={<a className="text-link" href="/results">Read the full record <ChevronRight size={14} /></a>} /><div className="evidence-grid"><div className="evidence-panel panel-surface"><div className="panel-heading compact"><div><h2>Changes CSG detected</h2><p>State changes found on the Windows machine.</p></div><span className="number-badge">{findings.length}</span></div>{findings.slice(0, 5).map((finding) => <div className="finding-line" key={finding.finding_id}><span className={`severity-dot ${finding.risk.severity.toLowerCase()}`} /><div><strong>{finding.object_key || finding.category}</strong><small>{finding.category} · {finding.reconciliation.status} · {finding.authorization_status}</small></div><b>{finding.risk.total}</b></div>)}{!findings.length && <Empty label="No changes recorded yet" />}</div><div className="evidence-panel panel-surface"><div className="panel-heading compact"><div><h2>Related activity</h2><p>Findings grouped into one investigation.</p></div><span className="number-badge">{incidents.length}</span></div>{incidents.slice(0, 5).map((incident) => <div className="incident-line" key={incident.incident_id}><span className="incident-icon"><GitBranch size={15} /></span><div><strong>{incident.title}</strong><small>{incident.status} · {incident.finding_ids.length} finding{incident.finding_ids.length === 1 ? "" : "s"}</small></div><ChevronRight size={15} /></div>)}{!incidents.length && <Empty label="No related activity yet" />}</div></div></section>

        <section className="section-block"><SectionHeading eyebrow="04 / HISTORY" title="Previous tests" action={<span className="section-count"><Clock3 size={15} /> Updates every 15 seconds</span>} /><div className="run-table panel-surface"><div className="run-table-head"><span>Test</span><span>Expected</span><span>Result</span><span>What it produced</span><span>Started</span></div>{runs.slice(0, 8).map((run) => <div className="run-row" key={run.run_id}><span><strong>{run.scenario_id}</strong><small>{run.run_id.slice(0, 8)}</small></span><span className="muted-note">{run.ground_truth_classification}</span><span className={run.success ? "outcome-pass" : "outcome-fail"}>{run.success ? <Check size={14} /> : <CircleAlert size={14} />}{run.success ? "Passed" : "Needs review"}</span><span>{run.actual_observations.delta_count || 0} changes · {run.actual_observations.event_count || 0} events</span><span className="muted-note">{formatTime(run.started_at)}</span></div>)}{!runs.length && <Empty label="No tests have been run from this lab yet" />}</div></section>
      </div>
    </section>
  </main>;
}

function StatusTile({ icon, label, value, detail, tone }: { icon: ReactNode; label: string; value: string; detail: string; tone: string }) { return <div className={`status-tile ${tone}`}><span className="tile-icon">{icon}</span><div><span className="tile-label">{label}</span><strong>{value}</strong><small>{detail}</small></div></div>; }
function SectionHeading({ eyebrow, title, action }: { eyebrow: string; title: string; action?: ReactNode }) { return <div className="section-heading"><div><span className="section-eyebrow">{eyebrow}</span><h2>{title}</h2></div>{action}</div>; }
function OperationRow({ icon, title, detail, button, busy, onClick, disabled }: { icon: ReactNode; title: string; detail: string; button: string; busy: boolean; onClick: () => void; disabled?: boolean }) { return <div className="operation-row"><span className="operation-icon">{icon}</span><div><strong>{title}</strong><p>{detail}</p></div><button className="secondary-button" disabled={busy || disabled} onClick={onClick}>{busy ? <LoaderCircle className="spin" size={15} /> : <Play size={14} />}{busy ? "Working" : button}</button></div>; }
function IntegrationPanel({ title, icon, tone, rows, footer }: { title: string; icon: ReactNode; tone: string; rows: string[][]; footer: string }) { return <div className={`integration-panel panel-surface ${tone}`}><div className="integration-title"><span>{icon}</span><h3>{title}</h3><span className="connected-label"><span className="state-dot" /> Live</span></div><div className="integration-rows">{rows.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}</div><p className="integration-footer">{footer}</p></div>; }
function Empty({ label }: { label: string }) { return <div className="empty"><Clock3 size={17} /><span>{label}</span></div>; }
function actionMessage(payload: ActionResponse) { if (payload.action === "run_fixture_suite") return `Completed ${payload.success_count || 0}/${payload.run_count || 0} experiment runs.`; if (payload.action === "sync_host") return `Provider sync completed: ${payload.event_count || 0} events, ${payload.delta_count || 0} deltas, ${payload.finding_count || 0} findings.`; if (payload.action === "process_backlog") return `Backlog processed: ${payload.reconciliation_updates || 0} reconciliation updates.`; return `Incident correlation completed: ${payload.incident_count || 0} incidents returned.`; }
function formatTime(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
