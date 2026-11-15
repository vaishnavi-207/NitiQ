"""CLI:  python -m backend.app.guardian.train [--epochs 12] [--no-baseline] [--evaluate]"""
import argparse
import json

import numpy as np

from backend.app.db.database import get_db_connection
from backend.app.guardian.engine import _ensure_tables
from backend.app.guardian.training import train_all, evaluate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--n-normal", type=int, default=500)
    ap.add_argument("--n-attack", type=int, default=500)
    ap.add_argument("--no-baseline", action="store_true", help="ignore rows recorded in 'learn' mode")
    ap.add_argument("--evaluate", action="store_true")
    a = ap.parse_args()
    rows = None
    if not a.no_baseline:
        _ensure_tables()
        with get_db_connection() as c:
            rows = [json.loads(r[0]) for r in c.execute("SELECT vec_json FROM guardian_features")]
        rows = np.array(rows) if rows else None
    train_all(rows, n_normal=a.n_normal, n_attack=a.n_attack, epochs=a.epochs)
    if a.evaluate:
        print(json.dumps(evaluate(), indent=2))


if __name__ == "__main__":
    main()
