"""Pure-NumPy GRU + survival head (no deep-learning framework needed).

Input : (batch, 10, 21)  -> last 10 seconds x [20 features + IF score]
Hidden: 64-number summary of the window (the "not human-readable" vector)
Head  : 3 sigmoid outputs = P(loss within 5 s), P(loss within 10 s), P(loss within 30 s)
Trained with back-propagation through time + Adam.
"""
import numpy as np


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -30, 30)))


class GRUSurvival:
    def __init__(self, input_dim=21, hidden=64, n_out=3, seed=0):
        rng = np.random.default_rng(seed)
        H, D = hidden, input_dim
        self.D, self.H, self.K = D, H, n_out
        self.p = {
            "Wx": rng.normal(0, 1 / np.sqrt(D), (D, 3 * H)),
            "Uh": rng.normal(0, 1 / np.sqrt(H), (H, 3 * H)),
            "b": np.zeros(3 * H),
            "Wo": rng.normal(0, 1 / np.sqrt(H), (H, n_out)),
            "bo": np.full(n_out, -2.0),
        }
        self._m = {k: np.zeros_like(v) for k, v in self.p.items()}
        self._v = {k: np.zeros_like(v) for k, v in self.p.items()}
        self._t = 0

    # ---------------- forward ----------------
    def forward(self, X, cache=False):
        B, T, _ = X.shape
        H = self.H
        Wx, Uh, b = self.p["Wx"], self.p["Uh"], self.p["b"]
        h = np.zeros((B, H))
        steps = []
        for t in range(T):
            x = X[:, t, :]
            gx = x @ Wx + b
            gh = h @ Uh
            z = _sigmoid(gx[:, :H] + gh[:, :H])
            r = _sigmoid(gx[:, H:2 * H] + gh[:, H:2 * H])
            ghn = gh[:, 2 * H:]
            n = np.tanh(gx[:, 2 * H:] + r * ghn)
            h_new = (1 - z) * n + z * h
            if cache:
                steps.append((x, h, z, r, n, ghn))
            h = h_new
        logits = h @ self.p["Wo"] + self.p["bo"]
        if cache:
            return logits, h, steps
        return logits, h

    def predict(self, X):
        """Returns (probabilities (B,K), 64-number summary (B,H))."""
        logits, h = self.forward(X)
        return _sigmoid(logits), h

    # ---------------- loss + backward ----------------
    def loss_and_grads(self, X, Y, M):
        """Masked binary cross-entropy over the K horizons."""
        logits, h_last, steps = self.forward(X, cache=True)
        P = _sigmoid(logits)
        eps = 1e-7
        denom = max(M.sum(), 1.0)
        loss = -(M * (Y * np.log(P + eps) + (1 - Y) * np.log(1 - P + eps))).sum() / denom
        dlog = (P - Y) * M / denom

        g = {k: np.zeros_like(v) for k, v in self.p.items()}
        g["Wo"] = h_last.T @ dlog
        g["bo"] = dlog.sum(0)
        dh = dlog @ self.p["Wo"].T
        H = self.H
        Wx, Uh = self.p["Wx"], self.p["Uh"]
        for (x, h_prev, z, r, n, ghn) in reversed(steps):
            dn = dh * (1 - z)
            dz = dh * (h_prev - n)
            dh_prev = dh * z
            dn_pre = dn * (1 - n ** 2)
            dr = dn_pre * ghn
            dghn = dn_pre * r
            dz_pre = dz * z * (1 - z)
            dr_pre = dr * r * (1 - r)
            dgx = np.concatenate([dz_pre, dr_pre, dn_pre], axis=1)
            dgh = np.concatenate([dz_pre, dr_pre, dghn], axis=1)
            g["Wx"] += x.T @ dgx
            g["b"] += dgx.sum(0)
            g["Uh"] += h_prev.T @ dgh
            dh = dh_prev + dgh @ Uh.T
        return loss, g

    def adam_step(self, grads, lr=3e-3, b1=0.9, b2=0.999, clip=5.0):
        norm = np.sqrt(sum((g ** 2).sum() for g in grads.values()))
        scale = min(1.0, clip / (norm + 1e-12))
        self._t += 1
        for k in self.p:
            g = grads[k] * scale
            self._m[k] = b1 * self._m[k] + (1 - b1) * g
            self._v[k] = b2 * self._v[k] + (1 - b2) * g * g
            mh = self._m[k] / (1 - b1 ** self._t)
            vh = self._v[k] / (1 - b2 ** self._t)
            self.p[k] -= lr * mh / (np.sqrt(vh) + 1e-8)

    # ---------------- persistence ----------------
    def state(self):
        return {"D": self.D, "H": self.H, "K": self.K, **{f"p_{k}": v for k, v in self.p.items()}}

    @classmethod
    def from_state(cls, s):
        m = cls(int(s["D"]), int(s["H"]), int(s["K"]))
        for k in m.p:
            m.p[k] = np.array(s[f"p_{k}"], dtype=np.float64)
        return m
