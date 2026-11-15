/**
 * NitiQ API service — Guardian real-time loop + health check.
 * All Guardian API calls are preserved exactly as the backend expects them.
 */

export interface HealthResponse {
  product: string;
  status: string;
  version: string;
  phase?: string;
  uptime_seconds?: number;
  python_version?: string;
  platform?: string;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api';

async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...options?.headers },
      ...options,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}: ${res.statusText}`);
    }
    return res.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      throw new Error(
        `Unable to connect to NitiQ API at ${url}. Ensure the backend is running (python -m uvicorn backend.app.main:app --port 8000).`
      );
    }
    throw err;
  }
}

export const apiService = {
  // ---- Health ----
  getHealth: () => fetchJson<HealthResponse>('/health'),

  // ---- Guardian: real-time time-to-loss loop ----
  guardianState: () => fetchJson<any>('/guardian/state'),

  guardianStart: (
    monitored_directory: string,
    consent_given: boolean,
    mode: 'guard' | 'learn',
    auto_suspend: boolean
  ) =>
    fetchJson<any>('/guardian/start', {
      method: 'POST',
      body: JSON.stringify({ monitored_directory, consent_given, mode, auto_suspend }),
    }),

  guardianStop: () => fetchJson<any>('/guardian/stop', { method: 'POST' }),

  guardianDecisions: (limit = 100, onlyActions = false) =>
    fetchJson<any[]>(`/guardian/decisions?limit=${limit}&only_actions=${onlyActions}`),

  guardianTrain: (use_baseline: boolean, n_normal = 500, n_attack = 500, epochs = 12) =>
    fetchJson<any>('/guardian/train', {
      method: 'POST',
      body: JSON.stringify({ use_baseline, n_normal, n_attack, epochs }),
    }),

  guardianTrainStatus: () => fetchJson<any>('/guardian/train/status'),

  guardianEvaluate: () => fetchJson<any>('/guardian/evaluate', { method: 'POST' }),

  guardianLastEvaluation: () => fetchJson<any>('/guardian/evaluation'),

  guardianSandbox: (n_files = 400, pre_backed_up_fraction = 0.4) =>
    fetchJson<any>('/guardian/demo/sandbox', {
      method: 'POST',
      body: JSON.stringify({ n_files, pre_backed_up_fraction }),
    }),

  guardianDemoAttack: (style: string, rate: number, delay = 1) =>
    fetchJson<any>('/guardian/demo/attack', {
      method: 'POST',
      body: JSON.stringify({ style, rate, delay }),
    }),

  guardianDemoStop: () => fetchJson<any>('/guardian/demo/stop', { method: 'POST' }),

  guardianConfirmSuspend: () =>
    fetchJson<any>('/guardian/suspend/confirm', { method: 'POST' }),

  guardianResume: (pid: number) =>
    fetchJson<any>(`/guardian/resume/${pid}`, { method: 'POST' }),

  guardianTerminate: (pid: number) =>
    fetchJson<any>(`/guardian/terminate/${pid}`, { method: 'POST' }),
};
