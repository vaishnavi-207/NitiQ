"""
NitiQ - SAFE Sandbox Ransomware Emulator Engine
Generates synthetic, deterministic ransomware behavior telemetry inside a strictly
isolated temporary sandbox directory containing dummy files.
Modifies ONLY its own temporary dummy files. Never executes real encryption,
exploits, network propagation, or destructive commands.
"""

import os
import shutil
import tempfile
import time
from typing import Dict, List, Any

from backend.app.telemetry.features import FEATURE_SCHEMA_VERSION


class SafeSandboxEmulator:
    """Generates synthetic multi-stage ransomware attack telemetry in isolated sandbox."""

    def generate_emulator_telemetry_windows(self) -> List[Dict[str, Any]]:
        """
        Executes non-destructive, synthetic attack stages on dummy files in temporary sandbox:
        Stage 1: Recon & Canary Burst (burst)
        Stage 2: Mass File Rename & Extension Hijack (mass_rename)
        Stage 3: High-Entropy Encryption Writes (high_entropy_write)
        Stage 4: Backup Repos & Decoy File Compromise (decoy_touch)

        Returns list of 5-second feature windows tagged with stage and is_malicious=True.
        """
        sandbox_dir = tempfile.mkdtemp(prefix="nitiq_safe_sandbox_")
        windows: List[Dict[str, Any]] = []

        try:
            # Create dummy test files inside sandbox
            dummy_files = []
            for i in range(25):
                fpath = os.path.join(sandbox_dir, f"doc_{i}.txt")
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(f"Sample benign text content line {i}\n" * 5)
                dummy_files.append(fpath)

            base_time = time.time()

            # STAGE 1: Recon & Rapid File Access Burst (burst)
            windows.append({
                "window_start": base_time + 5.0,
                "window_end": base_time + 10.0,
                "event_count": 42,
                "create_count": 2,
                "modify_count": 35,
                "delete_count": 0,
                "move_rename_count": 5,
                "extension_change_count": 0,
                "file_size_delta_bytes": 12400.0,
                "write_throughput_bytes_per_sec": 2480.0,
                "distinct_files_count": 20,
                "distinct_dirs_count": 2,
                "high_entropy_ratio": 0.05,
                "avg_entropy": 4.1,
                "decoy_touches_count": 0,
                "top_process_name": "cmd.exe",
                "is_malicious": True,
                "stage_tag": "burst",
                "schema_version": FEATURE_SCHEMA_VERSION,
            })

            # STAGE 2: Mass Extension Hijack & Rename (mass_rename)
            windows.append({
                "window_start": base_time + 10.0,
                "window_end": base_time + 15.0,
                "event_count": 88,
                "create_count": 0,
                "modify_count": 20,
                "delete_count": 0,
                "move_rename_count": 68,
                "extension_change_count": 65,
                "file_size_delta_bytes": 85000.0,
                "write_throughput_bytes_per_sec": 17000.0,
                "distinct_files_count": 25,
                "distinct_dirs_count": 3,
                "high_entropy_ratio": 0.35,
                "avg_entropy": 5.8,
                "decoy_touches_count": 0,
                "top_process_name": "vssadmin.exe",
                "is_malicious": True,
                "stage_tag": "mass_rename",
                "schema_version": FEATURE_SCHEMA_VERSION,
            })

            # STAGE 3: High-Entropy Encryption Writes (high_entropy_write)
            windows.append({
                "window_start": base_time + 15.0,
                "window_end": base_time + 20.0,
                "event_count": 140,
                "create_count": 10,
                "modify_count": 115,
                "delete_count": 5,
                "move_rename_count": 10,
                "extension_change_count": 8,
                "file_size_delta_bytes": 520000.0,
                "write_throughput_bytes_per_sec": 104000.0,
                "distinct_files_count": 30,
                "distinct_dirs_count": 4,
                "high_entropy_ratio": 0.92,
                "avg_entropy": 7.95,
                "decoy_touches_count": 0,
                "top_process_name": "powershell.exe",
                "is_malicious": True,
                "stage_tag": "high_entropy_write",
                "schema_version": FEATURE_SCHEMA_VERSION,
            })

            # STAGE 4: Backup Repos & Decoy File Touch (decoy_touch)
            windows.append({
                "window_start": base_time + 20.0,
                "window_end": base_time + 25.0,
                "event_count": 35,
                "create_count": 1,
                "modify_count": 25,
                "delete_count": 8,
                "move_rename_count": 1,
                "extension_change_count": 1,
                "file_size_delta_bytes": 18000.0,
                "write_throughput_bytes_per_sec": 3600.0,
                "distinct_files_count": 12,
                "distinct_dirs_count": 2,
                "high_entropy_ratio": 0.40,
                "avg_entropy": 6.2,
                "decoy_touches_count": 2,
                "top_process_name": "wbadmin.exe",
                "is_malicious": True,
                "stage_tag": "decoy_touch",
                "schema_version": FEATURE_SCHEMA_VERSION,
            })

            return windows
        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
