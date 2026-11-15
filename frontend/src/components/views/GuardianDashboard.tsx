/**
 * GuardianDashboard — NitiQ real-time file-loss prevention dashboard.
 *
 * Layout:
 *   Header (brand + API status + Guardian status)
 *   Top Row: Risk Overview | Survival Forecast | Response Action
 *   Monitoring Row: 6 file-event counters
 *   Setup & Controls (collapsible)
 *   Activity Log
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ShieldAlert,
  Eye,
  ShieldCheck,
  PauseCircle,
  Radar,
  Play,
  Square,
  Cpu,
  FlaskConical,
  RotateCcw,
  Skull,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertCircle,
  Activity,
  BarChart3,
} from 'lucide-react';
import { apiService } from '../../services/api';

// ---- constants -------------------------------------------------------

const ACTION = {
  WATCH: { cls: 'watch', color: 'var(--green)', label: 'WATCH', hint: 'No risk — monitoring normally' },
  SHIELD: { cls: 'shield', color: 'var(--amber)', label: 'SHIELD', hint: 'Backing up at-risk files' },
  SUSPEND: { cls: 'suspend', color: 'var(--red)', label: 'SUSPEND', hint: 'Suspicious program paused' },
  LEARN: { cls: 'idle', color: 'var(--cyan)', label: 'LEARNING', hint: 'Recording normal behaviour' },
  IDLE: { cls: 'idle', color: 'var(--text-muted)', label: 'IDLE', hint: 'Start the Guardian to begin' },
} as const;

type ActionKey = keyof typeof ACTION;

const pct = (x: number | undefined) => `${Math.round((x ?? 0) * 100)}%`;
const fmt = (n: number | undefined, dec = 2) =>
  n === undefined || n === null ? '—' : n.toFixed(dec);

// ---- sub-components --------------------------------------------------

const ProbBar: React.FC<{ label: string; value: number; color: string }> = ({
  label,
  value,
  color,
}) => (
  <div className="prob-bar">
    <div className="prob-bar-header">
      <span>{label}</span>
      <strong style={{ color, fontFamily: 'var(--mono)' }}>{pct(value)}</strong>
    </div>
    <div className="prob-bar-track">
      <div
        className="prob-bar-fill"
        style={{ width: `${Math.min(100, value * 100)}%`, background: color }}
      />
    </div>
  </div>
);

// ---- main component --------------------------------------------------

export const GuardianDashboard: React.FC = () => {
  // state
  const [st, setSt] = useState<any>(null);
  const [decisions, setDecisions] = useState<any[]>([]);
  const [onlyActions, setOnlyActions] = useState(false);
  const [dir, setDir] = useState('backend/data/sandbox');
  const [consent, setConsent] = useState(false);
  const [autoSuspend, setAutoSuspend] = useState(true);
  const [rate, setRate] = useState(15);
  const [useBaseline, setUseBaseline] = useState(true);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [train, setTrain] = useState<any>(null);
  const [evalRes, setEvalRes] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const [controlsOpen, setControlsOpen] = useState(true);
  const onlyRef = useRef(onlyActions);
  onlyRef.current = onlyActions;

  // helpers
  const poll = useCallback(async () => {
    try {
      const s = await apiService.guardianState();
      setSt(s);
      setDecisions(await apiService.guardianDecisions(80, onlyRef.current));
      setErr((e) => (e && e.startsWith('Unable to connect') ? null : e));
    } catch (e: any) {
      setErr(e.message);
    }
  }, []);

  const checkHealth = useCallback(async () => {
    try {
      const h = await apiService.getHealth();
      setBackendOk(h.status === 'healthy');
    } catch {
      setBackendOk(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const hi = setInterval(checkHealth, 30_000);
    poll();
    const pi = setInterval(poll, 1_000);
    apiService.guardianLastEvaluation().then(setEvalRes).catch(() => undefined);
    return () => { clearInterval(hi); clearInterval(pi); };
  }, [poll, checkHealth]);

  useEffect(() => {
    if (!train || train.state !== 'running') return;
    const t = setInterval(async () => {
      const s = await apiService.guardianTrainStatus();
      setTrain(s);
      if (s.state !== 'running') poll();
    }, 1_500);
    return () => clearInterval(t);
  }, [train, poll]);

  const run = async (fn: () => Promise<any>, ok?: string) => {
    setBusy(true); setErr(null); setMsg(null);
    try {
      const r = await fn();
      setMsg(ok ?? (r ? JSON.stringify(r).slice(0, 160) : 'Done.'));
      await poll();
      return r;
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  // derived
  const running = !!st?.running;
  const L = st?.latest ?? {};
  const actionKey: ActionKey = running
    ? ((L.action as ActionKey) in ACTION ? (L.action as ActionKey) : 'WATCH')
    : 'IDLE';
  const act = ACTION[actionKey];
  const lostPct = Math.min(1, (st?.lost_files ?? 0) / (st?.loss_threshold ?? 50));
  const inSandbox = (st?.monitored_directory ?? dir).includes('sandbox');

  // risk colour
  const risk = L.risk ?? 0;
  const riskClass = risk >= 0.6 ? 'red' : risk >= 0.3 ? 'amber' : 'green';

  return (
    <div className="gd-layout">
      {/* ===== HEADER ===== */}
      <header className="gd-header">
        <div className="gd-brand">
          <div className="gd-brand-icon">
            <ShieldAlert size={18} />
          </div>
          <div>
            <div className="gd-brand-name">NitiQ</div>
            <div className="gd-brand-sub">FILE-LOSS PREVENTION</div>
          </div>
        </div>

        <div className="gd-header-right">
          {/* Guardian running indicator */}
          <div className="flex-row">
            <span
              className={`status-dot ${running ? 'green' : 'grey'}`}
              style={running ? { animation: 'pulse 2s infinite' } : {}}
            />
            <span style={{ fontSize: 12, color: running ? 'var(--green)' : 'var(--text-muted)', fontWeight: 600 }}>
              {running
                ? st?.mode === 'learn'
                  ? `Learning • ${st.learn_rows ?? 0} s recorded`
                  : `Monitoring • ${st.uptime_s ?? 0}s`
                : 'Guardian Idle'}
            </span>
          </div>

          {/* API status */}
          <div
            className="api-pill"
            onClick={checkHealth}
            title="Click to re-check backend connection"
          >
            {backendOk === null ? (
              <Activity size={13} style={{ color: 'var(--cyan)' }} />
            ) : backendOk ? (
              <><CheckCircle2 size={13} style={{ color: 'var(--green)' }} /><span style={{ color: 'var(--green)', fontWeight: 600 }}>API Connected</span></>
            ) : (
              <><AlertCircle size={13} style={{ color: 'var(--red)' }} /><span style={{ color: 'var(--red)', fontWeight: 600 }}>API Offline</span></>
            )}
          </div>
        </div>
      </header>

      {/* ===== BODY ===== */}
      <main className="gd-body">

        {/* error / success notices */}
        {err && <div className="notice error"><AlertCircle size={15} />{err}</div>}
        {msg && !err && <div className="notice ok"><CheckCircle2 size={15} />{msg}</div>}

        {/* ===== TOP ROW ===== */}
        <div className="gd-top">

          {/* A. Risk Overview */}
          <div className="panel">
            <div className="panel-title"><Radar size={13} /> System Risk</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="metric">
                <div className="metric-label">Overall Risk</div>
                <div className={`metric-value ${riskClass}`}>
                  {running ? pct(risk) : '—'}
                </div>
                <div className="metric-sub">
                  {running
                    ? risk >= 0.6 ? 'Critical' : risk >= 0.3 ? 'Elevated' : 'Normal'
                    : 'Start Guardian'}
                </div>
              </div>
              <div className="metric">
                <div className="metric-label">Anomaly Score (Isolation Forest)</div>
                <div
                  className="metric-value"
                  style={{ fontSize: 20, color: (L.if_score ?? 0) >= 0.5 ? 'var(--red)' : 'var(--cyan)' }}
                >
                  {running ? fmt(L.if_score) : '—'}
                </div>
                <div className="metric-sub">Score 0 – 1 &nbsp;|&nbsp; Unusual &gt; 0.5</div>
              </div>
              <div className="metric">
                <div className="metric-label">Backup Coverage</div>
                <div className="metric-value" style={{ fontSize: 20, color: 'var(--green)' }}>
                  {running ? pct(st?.backup_coverage) : '—'}
                </div>
                <div className="metric-sub">
                  {running
                    ? `${st?.unbacked_files ?? 0} files without backup`
                    : 'Scan on start'}
                </div>
              </div>
            </div>
          </div>

          {/* B. Survival Forecast */}
          <div className="panel">
            <div className="panel-title"><BarChart3 size={13} /> Survival Forecast</div>
            <ProbBar label="P(loss within 5 s)" value={L.p5 ?? 0} color="var(--red)" />
            <ProbBar label="P(loss within 10 s)" value={L.p10 ?? 0} color="var(--amber)" />
            <ProbBar label="P(loss within 30 s)" value={L.p30 ?? 0} color="#eab308" />

            <div className="divider" style={{ margin: '12px 0' }} />

            <div className="flex-between">
              <span className="text-muted" style={{ fontSize: 12 }}>Estimated time remaining</span>
              <strong
                style={{
                  fontSize: 28,
                  fontFamily: 'var(--mono)',
                  color: L.seconds_remaining != null ? 'var(--red)' : 'var(--green)',
                }}
              >
                {L.seconds_remaining != null ? `${L.seconds_remaining}s` : '> 30 s'}
              </strong>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="flex-between" style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 5 }}>
                <span>Files destroyed (unbacked)</span>
                <span style={{ fontFamily: 'var(--mono)', color: lostPct > 0 ? 'var(--red)' : 'var(--text-secondary)' }}>
                  {st?.lost_files ?? 0} / {st?.loss_threshold ?? 50}
                </span>
              </div>
              <div className="prob-bar-track">
                <div
                  className="prob-bar-fill"
                  style={{
                    width: `${lostPct * 100}%`,
                    background: lostPct > 0.6 ? 'var(--red)' : 'var(--amber)',
                  }}
                />
              </div>
            </div>
          </div>

          {/* C. Response Action */}
          <div className="panel" style={{ borderColor: running && actionKey !== 'IDLE' && actionKey !== 'WATCH' ? act.color : undefined }}>
            <div className="panel-title">
              {actionKey === 'SUSPEND' ? <PauseCircle size={13} /> : actionKey === 'SHIELD' ? <ShieldCheck size={13} /> : <Eye size={13} />}
              {' '}Response Policy
            </div>

            <div style={{ textAlign: 'center', paddingTop: 4, paddingBottom: 8 }}>
              <div className={`action-badge ${act.cls}`}>
                {actionKey === 'SUSPEND' ? <PauseCircle size={20} /> : actionKey === 'SHIELD' ? <ShieldCheck size={20} /> : <Eye size={20} />}
                {act.label}
              </div>
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-secondary)' }}>{act.hint}</div>
            </div>

            {/* Reasons */}
            {(L.reasons ?? []).length > 0 && (
              <div className="reasons">
                {(L.reasons as string[]).map((r, i) => (
                  <div key={i} className="reason-line">{r}</div>
                ))}
                {L.detail?.suspend && <div className="reason-line" style={{ color: 'var(--red)' }}>{L.detail.suspend}</div>}
                {L.detail?.shield && <div className="reason-line" style={{ color: 'var(--amber)' }}>{L.detail.shield}</div>}
              </div>
            )}

            {/* Suspect */}
            {L.suspect && (
              <div className="mt-8" style={{ fontSize: 12, color: 'var(--red)' }}>
                Suspect: <strong>{L.suspect.name}</strong> (pid {L.suspect.pid})
                {L.suspect.confidence && <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>{L.suspect.confidence}</span>}
              </div>
            )}

            {/* Confirm suspend prompt */}
            {st?.pending_suspend && (
              <div style={{ marginTop: 12, padding: '8px 10px', border: '1px solid var(--red-border)', borderRadius: 6, fontSize: 12 }}>
                Confirm: pause <strong>{st.pending_suspend.name}</strong> (pid {st.pending_suspend.pid})?
                <button
                  className="btn btn-danger"
                  style={{ marginLeft: 10 }}
                  onClick={() => run(() => apiService.guardianConfirmSuspend())}
                >
                  Pause it
                </button>
              </div>
            )}

            {/* Suspended programs */}
            {(st?.suspended ?? []).map((p: any) => (
              <div key={p.pid} className="suspended-row">
                <PauseCircle size={13} />
                <span style={{ flex: 1 }}>{p.name} (pid {p.pid}) paused</span>
                <button className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: 11 }} onClick={() => run(() => apiService.guardianResume(p.pid), 'Resumed.')}>
                  <RotateCcw size={11} /> Resume
                </button>
                <button className="btn btn-danger" style={{ padding: '3px 8px', fontSize: 11 }} onClick={() => run(() => apiService.guardianTerminate(p.pid), 'Terminated.')}>
                  <Skull size={11} /> Kill
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* ===== REAL-TIME MONITORING ===== */}
        <div>
          <div className="panel-title" style={{ marginBottom: 8, paddingLeft: 2 }}>
            <Activity size={13} /> Real-Time File Activity
          </div>
          <div className="gd-monitoring">
            <MonCell label="Created" value={L.features?.create_count} />
            <MonCell label="Modified" value={L.features?.modify_count} />
            <MonCell label="Deleted" value={L.features?.delete_count} sub="this second" />
            <MonCell label="Renamed" value={L.features?.rename_count} />
            <MonCell
              label="Canary Hits"
              value={st?.canary_hits_total}
              highlight={!!(st?.canary_hits_total)}
              highlightColor="var(--red)"
              sub={`${(st?.canaries ?? []).length} decoy files`}
            />
            <MonCell
              label="Backup Coverage"
              value={running ? Math.round((st?.backup_coverage ?? 0) * 100) : undefined}
              suffix="%"
              sub={`${st?.files_tracked ?? 0} files tracked`}
            />
          </div>
        </div>

        {/* canary notice */}
        {!!(st?.canary_hits_total) && (
          <div className="notice warn">
            <AlertCircle size={14} />
            Canary (decoy) file touched {st.canary_hits_total} time(s) — a program may be scanning or modifying unexpected files.
          </div>
        )}

        {/* ===== SETUP & CONTROLS ===== */}
        <div className="panel">
          <div
            className="collapsible-header"
            onClick={() => setControlsOpen((v) => !v)}
          >
            <div className="panel-title" style={{ marginBottom: 0 }}>
              <FlaskConical size={13} /> Setup &amp; Controls
            </div>
            {controlsOpen ? <ChevronUp size={15} style={{ color: 'var(--text-muted)' }} /> : <ChevronDown size={15} style={{ color: 'var(--text-muted)' }} />}
          </div>

          {controlsOpen && (
            <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Folder + consent */}
              <div className="ctrl-row">
                <input
                  className="ctrl-input"
                  value={dir}
                  onChange={(e) => setDir(e.target.value)}
                  disabled={running}
                  placeholder="Folder path to monitor"
                />
                <label className="ctrl-label">
                  <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} disabled={running} />
                  I consent to monitor this folder
                </label>
                <label className="ctrl-label">
                  <input type="checkbox" checked={autoSuspend} onChange={(e) => setAutoSuspend(e.target.checked)} disabled={running} />
                  Auto-suspend
                </label>
              </div>

              {/* Primary actions */}
              <div className="ctrl-row">
                <button
                  className="btn btn-ghost"
                  disabled={busy || running}
                  onClick={() => run(() => apiService.guardianSandbox(400, 0.4), 'Demo sandbox created (400 files, 40% pre-backed-up).')}
                >
                  <FlaskConical size={14} /> Create Demo Sandbox
                </button>
                <button
                  className="btn btn-ghost"
                  disabled={busy || train?.state === 'running'}
                  onClick={async () => setTrain(await run(() => apiService.guardianTrain(useBaseline), 'Training started…'))}
                >
                  <Cpu size={14} /> {st?.models_ready ? 'Re-train Models' : 'Train Models'}
                </button>
                <label className="ctrl-label" style={{ fontSize: 12 }}>
                  <input type="checkbox" checked={useBaseline} onChange={(e) => setUseBaseline(e.target.checked)} />
                  Use my recorded baseline
                </label>

                {!running ? (
                  <>
                    <button
                      className="btn btn-primary"
                      disabled={busy || !consent || !st?.models_ready}
                      onClick={() => run(() => apiService.guardianStart(dir, consent, 'guard', autoSuspend), 'Guardian is running.')}
                      title={!st?.models_ready ? 'Train models first' : !consent ? 'Enable consent checkbox' : ''}
                    >
                      <Play size={14} /> Start Guardian
                    </button>
                    <button
                      className="btn btn-ghost"
                      disabled={busy || !consent}
                      onClick={() => run(() => apiService.guardianStart(dir, consent, 'learn', autoSuspend), 'Learning normal behaviour. Use the folder for 10+ minutes, then Stop and Re-train.')}
                    >
                      <Eye size={14} /> Learn My Behaviour
                    </button>
                  </>
                ) : (
                  <button
                    className="btn btn-danger"
                    disabled={busy}
                    onClick={() => run(() => apiService.guardianStop(), 'Guardian stopped.')}
                  >
                    <Square size={14} /> Stop
                  </button>
                )}
              </div>

              {/* Status messages */}
              {!st?.models_ready && (
                <div className="notice info" style={{ fontSize: 12 }}>
                  <Cpu size={13} />
                  No trained models yet. Click <strong>Train Models</strong> (~2 minutes) before starting the Guardian.
                </div>
              )}
              {st?.model_meta && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Models trained {st.model_meta.trained_at} &nbsp;·&nbsp; IF source: {st.model_meta.if_source} &nbsp;·&nbsp; GRU val loss: {st.model_meta.gru_val_loss}
                </div>
              )}
              {train && (
                <div className="train-log">
                  Training: <strong style={{ color: train.state === 'error' ? 'var(--red)' : 'var(--cyan)' }}>{train.state}</strong>
                  {train.log?.length > 0 && <> — {train.log[train.log.length - 1]}</>}
                  {train.error && <span style={{ color: 'var(--red)' }}> — {train.error}</span>}
                </div>
              )}
              {st?.mode === 'learn' && running && (
                <div className="notice info" style={{ fontSize: 12 }}>
                  <Eye size={13} />
                  Learning mode: <strong>{st.learn_rows}</strong> seconds recorded. Aim for 600+. Press Stop, then Re-train Models.
                </div>
              )}

              {/* Demo attack controls */}
              <div className="divider" />
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: 0.4, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
                  Safe Demo Activity (Sandbox Only)
                </div>
                <div className="ctrl-row">
                  <label className="ctrl-label" style={{ fontSize: 12 }}>
                    Speed:
                    <input
                      type="number"
                      min={1}
                      max={300}
                      value={rate}
                      onChange={(e) => setRate(Number(e.target.value))}
                      style={{
                        width: 64,
                        marginLeft: 6,
                        padding: '3px 7px',
                        background: 'var(--bg-main)',
                        color: 'var(--text-primary)',
                        border: '1px solid var(--border-mid)',
                        borderRadius: 4,
                        fontSize: 12,
                        fontFamily: 'var(--mono)',
                      }}
                    />
                    &nbsp;files/s
                  </label>
                  {(['rename', 'inplace', 'copy_delete'] as const).map((s) => (
                    <button
                      key={s}
                      className="btn btn-danger"
                      style={{ padding: '5px 12px', fontSize: 12 }}
                      disabled={busy || !running || !inSandbox}
                      onClick={() => run(() => apiService.guardianDemoAttack(s, rate), `Ransomware-like demo started (${s}).`)}
                    >
                      Attack: {s}
                    </button>
                  ))}
                  {(['benign_copy', 'benign_edit'] as const).map((s) => (
                    <button
                      key={s}
                      className="btn btn-ghost"
                      style={{ padding: '5px 12px', fontSize: 12 }}
                      disabled={busy || !running || !inSandbox}
                      onClick={() => run(() => apiService.guardianDemoAttack(s, Math.min(rate, 40)), `Harmless demo started (${s}).`)}
                    >
                      Harmless: {s}
                    </button>
                  ))}
                  <button
                    className="btn btn-ghost"
                    style={{ padding: '5px 12px', fontSize: 12 }}
                    disabled={!st?.demo_running}
                    onClick={() => run(() => apiService.guardianDemoStop(), 'Demo stopped.')}
                  >
                    Stop Demo
                  </button>
                </div>
                {!inSandbox && running && (
                  <div className="notice warn" style={{ marginTop: 8, fontSize: 11 }}>
                    <AlertCircle size={12} />
                    Demo attacks only run inside a NitiQ sandbox folder. Start the Guardian on the sandbox directory first.
                  </div>
                )}
              </div>

              {/* Evaluation */}
              <div className="divider" />
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: 0.4, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
                  Model Evaluation (Held-Out Simulated Runs)
                </div>
                <div className="ctrl-row">
                  <button
                    className="btn btn-ghost"
                    disabled={busy || !st?.models_ready}
                    onClick={async () => setEvalRes(await run(() => apiService.guardianEvaluate(), 'Evaluation complete.'))}
                  >
                    <BarChart3 size={14} /> Run Evaluation
                  </button>
                  {evalRes && (
                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      Action before loss: <strong style={{ color: 'var(--text-primary)' }}>{pct(evalRes.action_before_loss_rate)}</strong>
                      &nbsp;· Median lead: <strong style={{ color: 'var(--text-primary)' }}>{evalRes.median_lead_time_s}s</strong>
                      &nbsp;· False alarms/h: <strong style={{ color: 'var(--text-primary)' }}>{evalRes.false_alarm_seconds_per_hour_normal}</strong>
                    </span>
                  )}
                </div>
                {evalRes && (
                  <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7 }}>
                    Survival AUC → 5s: {evalRes.survival_quality?.['5s']?.auc} &nbsp;|&nbsp;
                    10s: {evalRes.survival_quality?.['10s']?.auc} &nbsp;|&nbsp;
                    30s: {evalRes.survival_quality?.['30s']?.auc}
                    &nbsp;· Mean error on "seconds remaining": {evalRes.mean_abs_error_seconds_remaining}s
                    <br />
                    <em>{evalRes.note}</em>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* ===== ACTIVITY LOG ===== */}
        <div className="panel">
          <div className="flex-between" style={{ marginBottom: 12 }}>
            <div className="panel-title" style={{ marginBottom: 0 }}>
              <Activity size={13} /> Activity Log
              <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>
                (every second stored in SQLite)
              </span>
            </div>
            <label className="ctrl-label" style={{ fontSize: 12 }}>
              <input
                type="checkbox"
                checked={onlyActions}
                onChange={(e) => setOnlyActions(e.target.checked)}
              />
              Only SHIELD / SUSPEND
            </label>
          </div>

          <div style={{ maxHeight: 300, overflowY: 'auto' }}>
            <table className="log-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Risk</th>
                  <th>IF Score</th>
                  <th>P5</th>
                  <th>P10</th>
                  <th>P30</th>
                  <th>Time Left</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {decisions.length === 0 ? (
                  <tr>
                    <td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '20px 10px' }}>
                      {running ? 'Collecting data…' : 'Start the Guardian to see activity.'}
                    </td>
                  </tr>
                ) : (
                  decisions.map((d, i) => {
                    const a = ACTION[(d.action as ActionKey) in ACTION ? (d.action as ActionKey) : 'WATCH'];
                    return (
                      <tr key={i}>
                        <td style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                          {new Date(d.t * 1000).toLocaleTimeString()}
                        </td>
                        <td className="action-cell" style={{ color: a.color }}>{d.action}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{pct(d.risk)}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{d.if_score?.toFixed(2)}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{pct(d.p5)}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{pct(d.p10)}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{pct(d.p30)}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>
                          {d.seconds_remaining != null ? `${d.seconds_remaining}s` : '—'}
                        </td>
                        <td style={{ color: 'var(--text-muted)', maxWidth: 280 }}>
                          {(d.reasons ?? []).slice(0, 2).join('; ')}
                          {d.detail?.suspend ? ` — ${d.detail.suspend}` : ''}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* footer */}
        <div style={{ textAlign: 'center', fontSize: 11, color: 'var(--text-muted)', paddingBottom: 8 }}>
          NitiQ · Monitor → Detect → Predict → Respond → Prevent File Loss
          &nbsp;·&nbsp; Only numerical feature metadata stored — never file contents.
        </div>
      </main>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
};

// ---- MonCell ---- 
const MonCell: React.FC<{
  label: string;
  value: number | undefined;
  sub?: string;
  highlight?: boolean;
  highlightColor?: string;
  suffix?: string;
}> = ({ label, value, sub, highlight, highlightColor, suffix = '' }) => (
  <div className="mon-cell">
    <div className="mon-cell-label">{label}</div>
    <div
      className="mon-cell-value"
      style={highlight ? { color: highlightColor } : undefined}
    >
      {value !== undefined && value !== null ? `${value}${suffix}` : '—'}
    </div>
    {sub && <div className="mon-cell-sub">{sub}</div>}
  </div>
);
