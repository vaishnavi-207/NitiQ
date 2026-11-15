"""Step 4 - Isolation Forest: learns this computer's normal second and scores each new second 0..1."""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from .schema import prep


class IFDetector:
    def __init__(self, seed=42):
        self.seed = seed
        self.scaler = StandardScaler()
        self.model = None
        self.q50 = self.q95 = self.q99 = 0.0

    def fit(self, X_raw):
        Z = self.scaler.fit_transform(prep(X_raw))
        self.model = IsolationForest(n_estimators=200, max_samples=min(256, len(Z)), contamination="auto",
                                     random_state=self.seed)
        self.model.fit(Z)
        a = -self.model.score_samples(Z)        # native anomaly score (higher = stranger)
        self.q50, self.q95, self.q99 = (float(np.percentile(a, q)) for q in (50, 95, 99))
        return self

    def score(self, X_raw):
        """Unusualness 0..1 (0.5 = the 95th percentile of this computer's normal behaviour)."""
        Z = self.scaler.transform(prep(X_raw))
        a = -self.model.score_samples(Z)
        width = max((self.q99 - self.q95) / 2.0, 1e-3)
        return 1.0 / (1.0 + np.exp(-np.clip((a - self.q95) / width, -30, 30)))
