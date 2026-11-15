"""
NitiQ - Telemetry Feature Extractor & Window Aggregator
Computes privacy-preserving numerical features over 5-second windows.
Never stores file contents, sampled bytes, sensitive filenames, or full paths.
"""

import math
import os
from typing import Dict, List, Any, Optional

FEATURE_SCHEMA_VERSION = "v1.0"

SUSPICIOUS_RANSOM_EXTENSIONS = {
  ".locked", ".crypto", ".encrypted", ".ransom", ".enc", ".crypted",
  ".locky", ".crypt", ".pay", ".wnry", ".ryuk", ".cerber"
}


def calculate_entropy_from_filepath(file_path: str, max_bytes: int = 4096) -> Optional[float]:
    """
    Computes Shannon entropy (0.0 to 8.0) on a bounded in-memory sample of the file.
    Immediately discards sample bytes.
    Does NOT follow symlinks outside target directories.
    Returns None if file cannot be read safely.
    """
    try:
        if not os.path.exists(file_path) or os.path.islink(file_path):
            return None
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return 0.0

        with open(file_path, "rb") as f:
            chunk = f.read(max_bytes)

        if not chunk:
            return 0.0

        byte_counts = [0] * 256
        for byte in chunk:
            byte_counts[byte] += 1

        entropy = 0.0
        total = len(chunk)
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return round(entropy, 4)
    except Exception:
        return None


def aggregate_raw_events_to_window(
    events: List[Dict[str, Any]],
    window_start: float,
    window_end: float,
    decoy_file_names: Optional[set] = None,
) -> Dict[str, Any]:
    """
    Aggregates raw event dictionaries into a single 5-second numerical feature window.
    Anonymizes all file paths into distinct counters.
    """
    window_duration = max(0.1, window_end - window_start)

    create_count = 0
    modify_count = 0
    delete_count = 0
    move_rename_count = 0
    extension_change_count = 0
    file_size_delta_bytes = 0.0
    distinct_files = set()
    distinct_dirs = set()
    decoy_touches = 0
    entropy_samples = []
    process_counts = {}

    decoy_names = decoy_file_names or {"DECOY_IMPORTANT_DOC.txt", "DECOY_FINANCE_2026.xlsx"}

    for ev in events:
        ev_type = ev.get("event_type", "")
        src_path = ev.get("src_path", "")
        dest_path = ev.get("dest_path", "")
        size_delta = ev.get("size_delta", 0.0)
        proc_name = ev.get("process_name", "unknown")

        if proc_name:
            process_counts[proc_name] = process_counts.get(proc_name, 0) + 1

        if src_path:
            filename = os.path.basename(src_path)
            dirname = os.path.dirname(src_path)
            distinct_files.add(filename)
            distinct_dirs.add(dirname)

            if filename in decoy_names:
                decoy_touches += 1

        if dest_path:
            dest_filename = os.path.basename(dest_path)
            dest_dirname = os.path.dirname(dest_path)
            distinct_files.add(dest_filename)
            distinct_dirs.add(dest_dirname)

            if dest_filename in decoy_names:
                decoy_touches += 1

        if ev_type == "created":
            create_count += 1
        elif ev_type == "modified":
            modify_count += 1
            file_size_delta_bytes += abs(size_delta)
            if "entropy" in ev and ev["entropy"] is not None:
                entropy_samples.append(ev["entropy"])
        elif ev_type == "deleted":
            delete_count += 1
        elif ev_type == "moved":
            move_rename_count += 1
            if src_path and dest_path:
                src_ext = os.path.splitext(src_path)[1].lower()
                dest_ext = os.path.splitext(dest_path)[1].lower()
                if src_ext != dest_ext or dest_ext in SUSPICIOUS_RANSOM_EXTENSIONS:
                    extension_change_count += 1

    avg_entropy = (
        round(sum(entropy_samples) / len(entropy_samples), 4)
        if entropy_samples
        else 0.0
    )
    high_entropy_count = sum(1 for e in entropy_samples if e >= 7.2)
    high_entropy_ratio = (
        round(high_entropy_count / len(entropy_samples), 4)
        if entropy_samples
        else 0.0
    )

    top_process = "unknown"
    if process_counts:
        top_process = max(process_counts, key=process_counts.get)

    return {
        "window_start": round(window_start, 2),
        "window_end": round(window_end, 2),
        "event_count": len(events),
        "create_count": create_count,
        "modify_count": modify_count,
        "delete_count": delete_count,
        "move_rename_count": move_rename_count,
        "extension_change_count": extension_change_count,
        "file_size_delta_bytes": round(file_size_delta_bytes, 2),
        "write_throughput_bytes_per_sec": round(file_size_delta_bytes / window_duration, 2),
        "distinct_files_count": len(distinct_files),
        "distinct_dirs_count": len(distinct_dirs),
        "high_entropy_ratio": high_entropy_ratio,
        "avg_entropy": avg_entropy,
        "decoy_touches_count": decoy_touches,
        "top_process_name": top_process,
        "is_malicious": False,
        "stage_tag": "normal",
        "schema_version": FEATURE_SCHEMA_VERSION,
    }
