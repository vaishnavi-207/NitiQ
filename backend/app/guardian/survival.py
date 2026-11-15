"""Survival layer: turns the GRU's three probabilities into 'seconds remaining'."""
import numpy as np
from .schema import HORIZONS


def monotone(p):
    """P(loss within 5s) <= P(within 10s) <= P(within 30s)."""
    return np.maximum.accumulate(np.asarray(p, dtype=np.float64), axis=-1)


def seconds_remaining(p, level=0.5):
    """Time at which the (piecewise-linear) loss CDF reaches `level`.
    Returns None if even P(loss within 30 s) is below `level` (i.e. > 30 s / no loss expected)."""
    p = monotone(p)
    ts = [0.0] + [float(h) for h in HORIZONS]
    ps = [0.0] + [float(x) for x in p]
    if ps[-1] < level:
        return None
    for i in range(1, len(ts)):
        if ps[i] >= level:
            lo, hi = ps[i - 1], ps[i]
            frac = 0.0 if hi == lo else (level - lo) / (hi - lo)
            return float(ts[i - 1] + frac * (ts[i] - ts[i - 1]))
    return None


def build_labels(T, loss_time):
    """Labels/masks for every second t: y_h = 1 if loss happens within h seconds.
    If no loss occurred (censored), a horizon extending beyond the run is masked out."""
    K = len(HORIZONS)
    Y = np.zeros((T, K))
    M = np.ones((T, K))
    t = np.arange(T)
    for j, h in enumerate(HORIZONS):
        if loss_time is not None:
            Y[:, j] = (t + h >= loss_time).astype(float)
        else:
            Y[:, j] = 0.0
            M[:, j] = (t + h < T).astype(float)  # only fully observed windows
    return Y, M
