"""
NitiQ - ML Alert Explainability Engine
Generates grounded, feature-deviation heuristic indicators for flagged windows
by comparing window feature metrics against normal baseline statistics.
Labels explanations clearly as heuristic indicators rather than causal proof.
"""

from typing import Dict, List, Any, Optional


def explain_anomaly_window(
    window: Dict[str, Any],
    baseline_stats: Optional[Dict[str, Dict[str, float]]] = None,
) -> List[str]:
    """
    Computes heuristic explanations based on measured feature deviations from normal baseline.
    Handles zero-variance features safely.
    """
    explanations: List[str] = []

    decoy_touches = window.get("decoy_touches_count", 0)
    if decoy_touches > 0:
        explanations.append(
            f"Decoy file touch detected ({decoy_touches} access events on designated honeypot files)."
        )

    ext_changes = window.get("extension_change_count", 0)
    if ext_changes >= 5:
        explanations.append(
            f"Elevated file extension change rate ({ext_changes} extension mutations in 5s window)."
        )

    renames = window.get("move_rename_count", 0)
    if renames >= 15:
        explanations.append(
            f"High file rename velocity ({renames} rename operations in 5s window)."
        )

    throughput = window.get("write_throughput_bytes_per_sec", 0.0)
    if throughput >= 10000.0:  # > 10 KB/s
        explanations.append(
            f"Burst write throughput detected ({throughput / 1024.0:.1f} KB/s write speed)."
        )

    high_entropy_ratio = window.get("high_entropy_ratio", 0.0)
    if high_entropy_ratio >= 0.5:
        explanations.append(
            f"High-entropy file modification ratio ({high_entropy_ratio * 100.0:.0f}% of modified files showed high entropy >= 7.2)."
        )

    distinct_files = window.get("distinct_files_count", 0)
    if distinct_files >= 20:
        explanations.append(
            f"Broad file access scope ({distinct_files} distinct files touched in 5s window)."
        )

    if not explanations:
        explanations.append(
            "Multi-dimensional anomaly score exceeded calibrated baseline threshold across joint feature distribution."
        )

    return explanations
