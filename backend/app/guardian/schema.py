"""Shared feature schema for the Guardian loop (the 20 numbers per second)."""
import numpy as np

FEATURE_NAMES = [
    "create_count",            # 0  files created this second
    "modify_count",            # 1  files modified
    "delete_count",            # 2  files deleted
    "rename_count",            # 3  files renamed / moved
    "ext_change_count",        # 4  renames that changed the file extension
    "bytes_written",           # 5  size of modified/created files (bytes)
    "distinct_files",          # 6  distinct files touched
    "distinct_dirs",           # 7  distinct folders touched
    "mean_entropy",            # 8  mean Shannon entropy of sampled modified files (0-8)
    "max_entropy",             # 9  max entropy of sampled files
    "high_entropy_ratio",      # 10 share of sampled files with entropy >= 7.2
    "entropy_jump_count",      # 11 files whose entropy jumped from low to high
    "canary_hits",             # 12 decoy (canary) files touched
    "backup_coverage",         # 13 share of monitored files that have a backup (0-1)
    "unbacked_damaged",        # 14 un-backed-up files modified/deleted/renamed this second
    "top_proc_write_Bps",      # 15 write rate of the busiest program (bytes/s)
    "top_proc_read_Bps",       # 16 read rate of that program (bytes/s)
    "rw_ratio",                # 17 read/write ratio of that program (0-4)
    "n_writer_procs",          # 18 number of programs writing right now
    "event_count",             # 19 total file events
]
N_FEATURES = len(FEATURE_NAMES)          # 20
GRU_INPUT_DIM = N_FEATURES + 1           # 20 features + Isolation Forest score
WINDOW_SECONDS = 10                      # GRU looks at the last 10 seconds
HORIZONS = (5, 10, 30)                   # survival horizons (seconds)
LOSS_THRESHOLD_FILES = 50                # "loss" = 50 un-backed-up files destroyed

_LOG_IDX = [0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 14, 15, 16, 18, 19]
_ENT_IDX = [8, 9]


def prep(X: np.ndarray) -> np.ndarray:
    """Variance-stabilising transform (log1p on counts/bytes, entropy/8, ratio/4)."""
    X = np.asarray(X, dtype=np.float64).copy()
    X = np.atleast_2d(X)
    X[:, _LOG_IDX] = np.log1p(np.maximum(X[:, _LOG_IDX], 0.0))
    X[:, _ENT_IDX] = X[:, _ENT_IDX] / 8.0
    X[:, 17] = np.clip(X[:, 17], 0.0, 4.0) / 4.0
    return X
