"""Train + evaluate the whole model stack (Isolation Forest -> GRU -> survival head)."""
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import roc_auc_score

from .gru import GRUSurvival
from .iforest import IFDetector
from .schema import GRU_INPUT_DIM, N_FEATURES, WINDOW_SECONDS, HORIZONS, prep
from .simulator import NORMAL_KINDS, ATTACK_KINDS, make_dataset, simulate_run
from .survival import build_labels, monotone, seconds_remaining

SAVED_DIR = Path("backend/app/guardian/saved")
W = WINDOW_SECONDS


def make_windows(X21):
    """(T,21) -> (T,W,21): window ending at each second (front padded by repeating the first row)."""
    T = X21.shape[0]
    pad = np.vstack([np.repeat(X21[:1], W - 1, axis=0), X21])
    idx = np.arange(T)[:, None] + np.arange(W)[None, :]
    return pad[idx]


def labels_for(T, loss_time, meta):
    """Survival labels. Seconds before an attack has begun carry no information (nothing is
    happening yet), so they are masked out instead of being labelled 'loss soon'."""
    Y, M = build_labels(T, loss_time)
    st = meta.get("attack_start")
    if st is not None:
        M[:max(st - 1, 0)] = 0.0
    return Y, M


def _norm_stats(runs_feats):
    Z = np.vstack(runs_feats)
    return Z.mean(0), Z.std(0) + 1e-6


def build_training_set(runs, iff):
    feats, Xs, Ys, Ms = [], [], [], []
    for X, loss_time, _ in runs:
        u = iff.score(X)
        Z = np.hstack([prep(X), u[:, None]])
        feats.append(Z)
    mu, sd = _norm_stats(feats)
    for (X, loss_time, meta), Z in zip(runs, feats):
        Y, M = labels_for(len(X), loss_time, meta)
        Xs.append(make_windows((Z - mu) / sd))
        Ys.append(Y)
        Ms.append(M)
    return np.concatenate(Xs), np.concatenate(Ys), np.concatenate(Ms), mu, sd


def train_all(baseline_rows=None, seed=7, n_normal=700, n_attack=700, epochs=14, batch=256, log=print):
    """Train IF on this computer's normal behaviour and the GRU/survival head on simulated runs.

    baseline_rows: optional (n,20) array of REAL per-second rows recorded in learn mode.
    """
    t0 = time.time()
    SAVED_DIR.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)

    # ---- Step 4: Isolation Forest on normal behaviour ----
    light = [simulate_run(rng, NORMAL_KINDS[int(rng.choice(7, p=[0.3, 0.3, 0.2, 0.06, 0.04, 0.06, 0.04]))])[0]
             for _ in range(250)]
    X_sim_norm = np.vstack(light)
    if baseline_rows is not None and len(baseline_rows) >= 60:
        real = np.asarray(baseline_rows, dtype=np.float64)
        reps = max(1, int(len(X_sim_norm) * 0.3 / max(len(real), 1)))
        X_if = np.vstack([real] * max(reps, 1) + [X_sim_norm[: int(len(X_sim_norm) * 0.7)]])
        if_source = f"real baseline ({len(real)} s) + simulated normal"
    else:
        X_if = X_sim_norm
        if_source = "simulated normal behaviour (no real baseline recorded)"
    iff = IFDetector(seed=42).fit(X_if)
    log(f"[IF] trained on {len(X_if)} seconds - {if_source}")

    # ---- Steps 5-6: GRU + survival head ----
    runs = make_dataset(n_normal, n_attack, seed=seed + 1)
    Xw, Y, M, mu, sd = build_training_set(runs, iff)
    n = len(Xw)
    order = rng.permutation(n)
    n_val = int(0.15 * n)
    val_idx, tr_idx = order[:n_val], order[n_val:]
    log(f"[GRU] {n} windows ({len(tr_idx)} train / {len(val_idx)} val), positives per horizon: "
        f"{[round(float(Y[:, j][M[:, j] > 0].mean()), 3) for j in range(len(HORIZONS))]}")
    gru = GRUSurvival(GRU_INPUT_DIM, 64, len(HORIZONS), seed=seed)
    best, best_state = 1e9, None
    for ep in range(epochs):
        rng.shuffle(tr_idx)
        lr = 4e-3 * (0.85 ** ep)
        tl, nb = 0.0, 0
        for i in range(0, len(tr_idx), batch):
            b = tr_idx[i:i + batch]
            loss, g = gru.loss_and_grads(Xw[b], Y[b], M[b])
            gru.adam_step(g, lr=lr)
            tl += loss
            nb += 1
        vl, _ = gru.loss_and_grads(Xw[val_idx], Y[val_idx], M[val_idx])
        log(f"[GRU] epoch {ep + 1}/{epochs} train {tl / nb:.4f} val {vl:.4f}")
        if vl < best:
            best, best_state = vl, gru.state()
    gru = GRUSurvival.from_state(best_state)

    joblib.dump({"iforest": iff}, SAVED_DIR / "iforest.joblib")
    np.savez(SAVED_DIR / "gru.npz", mu=mu, sd=sd, **gru.state())
    meta = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "if_source": if_source,
        "gru_val_loss": round(float(best), 4),
        "train_windows": int(len(tr_idx)),
        "seconds": round(time.time() - t0, 1),
        "horizons": list(HORIZONS),
    }
    (SAVED_DIR / "meta.json").write_text(json.dumps(meta, indent=2))
    log(f"[done] saved models in {meta['seconds']}s")
    return meta


class ModelStack:
    """Loaded IF + GRU used by the live engine and the evaluator."""

    def __init__(self):
        self.iff = joblib.load(SAVED_DIR / "iforest.joblib")["iforest"]
        z = np.load(SAVED_DIR / "gru.npz")
        self.mu, self.sd = z["mu"], z["sd"]
        self.gru = GRUSurvival.from_state({k: z[k] for k in z.files})
        self.meta = json.loads((SAVED_DIR / "meta.json").read_text()) if (SAVED_DIR / "meta.json").exists() else {}

    @staticmethod
    def available():
        return (SAVED_DIR / "gru.npz").exists() and (SAVED_DIR / "iforest.joblib").exists()

    def if_score(self, x_raw):
        return float(self.iff.score(np.asarray(x_raw).reshape(1, -1))[0])

    def infer(self, history21):
        """history21: (<=10, 21) raw rows [20 features + IF score]. Returns (probs(3), summary(64))."""
        H = np.asarray(history21, dtype=np.float64)
        Z = np.hstack([prep(H[:, :N_FEATURES]), H[:, N_FEATURES:]])
        Z = (Z - self.mu) / self.sd
        if len(Z) < W:
            Z = np.vstack([np.repeat(Z[:1], W - len(Z), axis=0), Z])
        probs, h = self.gru.predict(Z[None, -W:, :])
        return monotone(probs[0]), h[0]


# --------------------------- evaluation ---------------------------
def evaluate(seed=2024, n_normal=150, n_attack=150, policy_factory=None):
    """Held-out evaluation on freshly simulated runs (never seen in training)."""
    from .policy import ResponsePolicy
    stack = ModelStack()
    runs = make_dataset(n_normal, n_attack, seed=seed)
    P, Y, M = [], [], []
    lead, acted, missed = [], 0, 0
    fa_ticks, normal_secs = 0, 0
    fa_runs = 0
    if_only_lead, if_only_acted, if_fa = [], 0, 0
    rem_err = []
    for X, loss_time, meta in runs:
        is_normal = meta["kind"] in NORMAL_KINDS
        u = stack.iff.score(X)
        Z = np.hstack([prep(X), u[:, None]])
        Zn = (Z - stack.mu) / stack.sd
        probs, _ = stack.gru.predict(make_windows(Zn))
        probs = monotone(probs)
        yy, mm = labels_for(len(X), loss_time, meta)
        P.append(probs); Y.append(yy); M.append(mm)
        pol = ResponsePolicy()
        first_act = None
        any_fa = False
        for t in range(len(X)):
            rem = seconds_remaining(probs[t])
            dec = pol.decide(probs[t], rem, float(u[t]), canary_recent=int(X[max(0, t - 3):t + 1, 12].sum()),
                             unbacked_at_risk=int(max(0, (1 - X[t, 13]) * 1000)), has_suspect=True,
                             lost_files=0, backup_rate=100.0, now=t,
                             canary_destructive=(int(X[max(0, t - 3):t + 1, 12].sum()) if not is_normal else 0))
            if dec["action"] != "WATCH":
                if is_normal:
                    fa_ticks += 1
                    any_fa = True
                elif loss_time is not None and first_act is None and (meta["attack_start"] is None or t >= meta["attack_start"] - 1):
                    first_act = t
        if is_normal:
            if_fa += int((u > 0.5).sum())
            normal_secs += len(X)
            fa_runs += int(any_fa)
        elif loss_time is not None:
            # remaining-time error: at each second 1..20 s before loss
            for t in range(max(0, loss_time - 20), loss_time):
                r = seconds_remaining(probs[t])
                if r is not None:
                    rem_err.append(abs(r - (loss_time - t)))
            # IF-only alarm baseline: first second after attack start with u>0.5
            st = meta["attack_start"] or 0
            idx = np.where(u[st:] > 0.5)[0]
            if len(idx) and st + idx[0] <= loss_time:
                if_only_acted += 1
                if_only_lead.append(loss_time - (st + idx[0]))
            if first_act is not None and first_act <= loss_time:
                acted += 1
                lead.append(loss_time - first_act)
            else:
                missed += 1
    P = np.concatenate(P); Y = np.concatenate(Y); M = np.concatenate(M)
    per_h = {}
    for j, h in enumerate(HORIZONS):
        mk = M[:, j] > 0
        y, p = Y[mk, j], P[mk, j]
        try:
            auc = float(roc_auc_score(y, p))
        except ValueError:
            auc = None
        per_h[f"{h}s"] = {"auc": None if auc is None else round(auc, 4),
                          "brier": round(float(np.mean((p - y) ** 2)), 4),
                          "positive_rate": round(float(y.mean()), 3)}
    n_loss_runs = acted + missed
    return {
        "heldout_runs": {"normal": n_normal, "attack": n_attack, "attacks_that_reach_loss": n_loss_runs},
        "survival_quality": per_h,
        "action_before_loss_rate": round(acted / max(n_loss_runs, 1), 3),
        "median_lead_time_s": round(float(np.median(lead)), 1) if lead else None,
        "p10_lead_time_s": round(float(np.percentile(lead, 10)), 1) if lead else None,
        "false_alarm_seconds_per_hour_normal": round(fa_ticks / max(normal_secs, 1) * 3600, 1),
        "normal_runs_with_any_alarm": round(fa_runs / max(n_normal, 1), 3),
        "mean_abs_error_seconds_remaining": round(float(np.mean(rem_err)), 2) if rem_err else None,
        "baseline_isolation_forest_only": {
            "detect_before_loss_rate": round(if_only_acted / max(n_loss_runs, 1), 3),
            "median_lead_time_s": round(float(np.median(if_only_lead)), 1) if if_only_lead else None,
            "false_alarm_seconds_per_hour_normal": round(if_fa / max(normal_secs, 1) * 3600, 1),
        },
        "note": "Evaluated on held-out SIMULATED runs; see Limitations for the sim-to-real gap.",
    }
