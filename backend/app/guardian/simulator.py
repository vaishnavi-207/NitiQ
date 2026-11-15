"""Synthetic per-second telemetry for training/evaluating the GRU + survival layer.

Real ransomware logs are not safe or practical to collect, so we generate per-second
feature trajectories (same 20-number schema as the live collector) for
  * normal computers (idle, office, developer, bulk copy, unzip, app update, backup job)
  * ransomware-like behaviour (in-place, rename, copy+delete, low-and-slow, bursty)
and compute the *ground-truth time-to-loss*: the first second when 50 un-backed-up
files have been destroyed.  No real malware is involved - only numbers.
"""
import numpy as np
from .schema import N_FEATURES, LOSS_THRESHOLD_FILES

NORMAL_KINDS = ["idle", "office", "dev", "bulk_copy", "extract", "app_update", "backup_job"]
ATTACK_KINDS = ["inplace", "rename", "copy_delete", "slow", "bursty"]


def _poisson(rng, lam):
    return int(rng.poisson(max(lam, 0)))


def _fill_normal(rng, X, kind, F, cov):
    T = X.shape[0]
    t = 0
    while t < T:
        if kind == "idle":
            n_burst = 0 if rng.random() < 0.9 else 1
            dur = int(rng.integers(5, 20))
            for s in range(t, min(T, t + dur)):
                if rng.random() < 0.05:
                    _tick_normal(rng, X, s, mods=_poisson(rng, 1), creates=0, dels=0, hi_prob=0.4, cov=cov, F=F)
        elif kind == "office":
            dur = int(rng.integers(10, 40))
            for s in range(t, min(T, t + dur)):
                if rng.random() < 0.25:
                    _tick_normal(rng, X, s, mods=_poisson(rng, 2), creates=_poisson(rng, 0.3), dels=_poisson(rng, 0.1),
                                 hi_prob=0.5, cov=cov, F=F)
        elif kind == "dev":
            dur = int(rng.integers(5, 25))
            for s in range(t, min(T, t + dur)):
                if rng.random() < 0.6:
                    _tick_normal(rng, X, s, mods=_poisson(rng, 8), creates=_poisson(rng, 15), dels=_poisson(rng, 4),
                                 hi_prob=0.15, cov=cov, F=F, dirs=int(rng.integers(1, 5)))
        elif kind == "bulk_copy":
            dur = int(rng.integers(5, 40))
            rate = float(np.exp(rng.uniform(np.log(5), np.log(200))))
            hi = rng.uniform(0.3, 1.0)
            for s in range(t, min(T, t + dur)):
                _tick_normal(rng, X, s, mods=0, creates=_poisson(rng, rate), dels=0, hi_prob=hi, cov=cov, F=F,
                             dirs=int(rng.integers(1, 6)), size_scale=3.0, rw=rng.uniform(0.8, 1.2))
        elif kind == "extract":
            dur = int(rng.integers(3, 25))
            rate = float(np.exp(rng.uniform(np.log(10), np.log(300))))
            for s in range(t, min(T, t + dur)):
                _tick_normal(rng, X, s, mods=0, creates=_poisson(rng, rate), dels=0, hi_prob=rng.uniform(0.1, 0.7),
                             cov=cov, F=F, dirs=int(rng.integers(2, 12)), rw=rng.uniform(0.05, 0.4))
        elif kind == "app_update":
            dur = int(rng.integers(4, 15))
            for s in range(t, min(T, t + dur)):
                n = _poisson(rng, rng.uniform(3, 12))
                _tick_normal(rng, X, s, mods=n, creates=_poisson(rng, 3), dels=_poisson(rng, 2), hi_prob=0.85,
                             cov=cov, F=F, dirs=int(rng.integers(1, 4)), ext_changes=_poisson(rng, 1.5),
                             size_scale=2.0, rw=rng.uniform(0.3, 1.0))
        elif kind == "backup_job":
            dur = int(rng.integers(10, 40))
            for s in range(t, min(T, t + dur)):
                X[s, 16] += rng.uniform(1e6, 5e7)       # heavy reader
                X[s, 15] += rng.uniform(0, 2e4)
                X[s, 17] = min(4.0, X[s, 16] / max(X[s, 15], 1.0))
                X[s, 18] = 1
        t += int(rng.integers(20, 80))
    # rare benign canary touch (indexer / AV / user poking at the decoy)
    if rng.random() < 0.02:
        X[int(rng.integers(0, T)), 12] += 1


def _tick_normal(rng, X, s, mods, creates, dels, hi_prob, cov, F, dirs=None, ext_changes=0, size_scale=1.0, rw=None):
    n_hi = int(rng.binomial(mods + creates, min(1.0, hi_prob))) if (mods + creates) else 0
    entropy_jump = int(rng.binomial(mods, min(1.0, hi_prob * 0.5))) if mods else 0
    X[s, 0] += creates
    X[s, 1] += mods
    X[s, 2] += dels
    X[s, 3] += ext_changes
    X[s, 4] += ext_changes
    size = float(np.exp(rng.normal(10.5, 1.2))) * size_scale
    X[s, 5] += (mods + creates) * size
    files = mods + creates + dels + ext_changes
    X[s, 6] += files
    X[s, 7] += max(1, dirs if dirs else min(files, int(rng.integers(1, 3)))) if files else 0
    tot = mods + creates
    if tot:
        ratio = n_hi / tot
        X[s, 10] = ratio
        X[s, 8] = 4.5 + 3.3 * ratio + rng.normal(0, 0.2)
        X[s, 9] = min(8.0, X[s, 8] + 0.4 + 2.0 * (1 - ratio) * rng.random())
    X[s, 11] += entropy_jump
    dmg = entropy_jump + dels + ext_changes
    X[s, 14] += int(rng.binomial(dmg, max(0.0, 1.0 - cov))) if dmg else 0
    X[s, 19] += files
    X[s, 15] += X[s, 5] * rng.uniform(0.7, 1.0)
    X[s, 16] += X[s, 15] * (rw if rw is not None else rng.uniform(0.05, 1.5))
    X[s, 17] = min(4.0, X[s, 16] / max(X[s, 15], 1.0))
    X[s, 18] = max(X[s, 18], 1 + _poisson(rng, 0.3))


def simulate_run(rng, kind, T=None):
    """Returns (X (T,20), loss_time or None (index of first second with loss), meta)."""
    is_attack = kind in ATTACK_KINDS
    F = int(np.exp(rng.uniform(np.log(300), np.log(8000))))
    cov0 = float(rng.choice([rng.uniform(0.0, 0.3), rng.uniform(0.3, 0.9), rng.uniform(0.9, 1.0)],
                            p=[0.3, 0.5, 0.2]))
    if T is None:
        T = int(rng.integers(120, 220)) if is_attack else int(rng.integers(90, 200))
    X = np.zeros((T, N_FEATURES))
    bg = rng.choice(["idle", "office", "dev"], p=[0.4, 0.4, 0.2])
    if is_attack:
        _fill_normal(rng, X, bg, F, cov0)
    else:
        _fill_normal(rng, X, kind, F, cov0)
        if rng.random() < 0.4:   # overlay a second benign behaviour
            _fill_normal(rng, X, rng.choice(NORMAL_KINDS), F, cov0)
    cov = np.full(T, cov0)
    loss_time = None
    meta = {"kind": kind, "files": F, "cov0": cov0, "attack_start": None}

    if is_attack:
        start = int(rng.integers(12, max(13, T // 3)))
        meta["attack_start"] = start
        base_rate = float(np.exp(rng.uniform(np.log(2.0), np.log(250.0))))
        if kind == "slow":
            base_rate = float(rng.uniform(0.4, 3.0))
        shield = rng.random() < 0.35          # defender backing files up during the attack
        shield_start = start + int(rng.integers(3, 15))
        shield_rate = rng.uniform(20, 300)
        n_can = int(rng.integers(2, 9))
        canary_pos = np.sort(rng.uniform(0, F, n_can))
        processed, destroyed, c_idx = 0, 0, 0
        ramp = int(rng.integers(1, 6))
        burst_on = True
        for s in range(start, T):
            k = s - start
            rate = base_rate * min(1.0, (k + 1) / ramp)
            if kind == "bursty":
                if rng.random() < 0.15:
                    burst_on = not burst_on
                rate = rate if burst_on else rate * 0.02
            n = min(_poisson(rng, rate), F - processed)
            if n <= 0:
                continue
            if shield and s >= shield_start:
                cov[s:] = np.minimum(1.0, cov[s:] + shield_rate / F)
            q = max(0.0, 1.0 - cov[s])
            hit_unbacked = int(rng.binomial(n, q))
            processed += n
            destroyed += hit_unbacked
            size = float(np.exp(rng.normal(11.0, 1.0)))
            ent = rng.normal(7.8, 0.1)
            if kind in ("inplace", "slow", "bursty"):
                X[s, 1] += n
                X[s, 11] += n * rng.uniform(0.85, 1.0)
            elif kind == "rename":
                X[s, 1] += n
                X[s, 3] += n
                X[s, 4] += n
                X[s, 11] += n * rng.uniform(0.85, 1.0)
            else:  # copy_delete
                X[s, 0] += n
                X[s, 2] += n
                X[s, 11] += n * rng.uniform(0.0, 0.3)
            X[s, 5] += n * size
            X[s, 6] += n
            X[s, 7] += max(1, int(n / rng.uniform(4, 40)))
            old = X[s, 1] - n if kind != "copy_delete" else 0
            ratio_new = 1.0 if kind == "copy_delete" else n / max(X[s, 1], 1)
            X[s, 8] = X[s, 8] * (1 - ratio_new) + ent * ratio_new if X[s, 8] else ent
            X[s, 9] = max(X[s, 9], min(8.0, ent + 0.15))
            tot_sampled = max(X[s, 1] + X[s, 0], 1)
            X[s, 10] = min(1.0, (n * rng.uniform(0.9, 1.0) + X[s, 10] * max(old, 0)) / tot_sampled)
            X[s, 14] += hit_unbacked
            X[s, 19] += n * (2 if kind in ("rename", "copy_delete") else 1)
            X[s, 15] += n * size
            X[s, 16] += n * size * rng.uniform(0.85, 1.15)
            X[s, 17] = min(4.0, X[s, 16] / max(X[s, 15], 1.0))
            X[s, 18] = max(X[s, 18], 1 + _poisson(rng, 0.4))
            while c_idx < n_can and processed >= canary_pos[c_idx]:
                X[s, 12] += 1
                c_idx += 1
            if loss_time is None and destroyed >= LOSS_THRESHOLD_FILES:
                loss_time = s
        meta["canary_first"] = None
    X[:, 13] = cov
    # sensor noise on the process-level numbers
    X[:, 15] *= np.exp(rng.normal(0, 0.1, T))
    X[:, 16] *= np.exp(rng.normal(0, 0.1, T))
    X[:, 17] = np.clip(X[:, 16] / np.maximum(X[:, 15], 1.0), 0, 4)
    X[(X[:, 19] == 0), 15:19] = 0.0       # process columns only matter when files are active
    if loss_time is not None:              # nothing left to forecast a few seconds after the loss
        X = X[: min(T, loss_time + 3)]
    return X, loss_time, meta


def make_dataset(n_normal, n_attack, seed):
    rng = np.random.default_rng(seed)
    runs = []
    for _ in range(n_normal):
        k = NORMAL_KINDS[int(rng.choice(len(NORMAL_KINDS), p=[0.15, 0.22, 0.15, 0.14, 0.1, 0.14, 0.10]))]
        runs.append(simulate_run(rng, k))
    for _ in range(n_attack):
        k = ATTACK_KINDS[int(rng.choice(len(ATTACK_KINDS), p=[0.3, 0.25, 0.2, 0.12, 0.13]))]
        runs.append(simulate_run(rng, k))
    return runs
