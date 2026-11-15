# NitiQ — Real-Time File-Loss Prevention System

**NitiQ** is a machine-learning-based system that monitors file and program activity on a computer every second, predicts how much time is left before files are permanently lost, and takes timely action to prevent or reduce that loss.

> **Safety notice:** NitiQ is strictly defensive. It never executes real attack code, encrypts files, or contacts external services. The demo sandbox operates only on dummy files inside a designated folder. All stored data is numerical feature metadata — file contents are never read, stored, or transmitted.

---

## How It Works — The 8-Stage Methodology

| Stage | What happens | Key file |
|---|---|---|
| **1. System Setup** | Load trained ML models. Place canary (decoy) files. Record which files have backups. | `guardian/engine.py` |
| **2. Data Collection** | Every second: file create / modify / delete / rename events (watchdog) + per-program read/write bytes (psutil). | `guardian/collector.py` |
| **3. Feature Extraction** | 20 numerical features per second (entropy, file ops, canary hits, backup coverage, process I/O). | `guardian/collector.py`, `guardian/schema.py` |
| **4. Isolation Forest** | 1 × 20 feature vector → unusualness score 0–1, trained on this computer's normal behaviour. | `guardian/iforest.py` |
| **5. GRU Model** | Last 10 s × [20 features + IF score] → 64-number summary of the activity window. | `guardian/gru.py` |
| **6. Survival Layer** | P(loss within 5 / 10 / 30 s) + estimated seconds remaining before 50 un-backed-up files are destroyed. | `guardian/survival.py` |
| **7. Response Policy** | WATCH / SHIELD (back up at-risk files) / SUSPEND (pause the offending program). | `guardian/policy.py` |
| **8. Dashboard** | Real-time display of all outputs; every decision logged to SQLite. | `frontend/src/components/views/GuardianDashboard.tsx` |

---

## Project Structure

```
NitiQ/
├── backend/
│   ├── app/
│   │   ├── main.py                   # FastAPI application
│   │   ├── api/
│   │   │   ├── guardian.py           # Guardian REST API (12 endpoints)
│   │   │   └── health.py             # Health check
│   │   ├── guardian/                 # Core 8-stage loop
│   │   │   ├── engine.py             # Main loop orchestrator
│   │   │   ├── collector.py          # Steps 2–3: data collection + 20 features
│   │   │   ├── schema.py             # Feature names + constants
│   │   │   ├── iforest.py            # Step 4: Isolation Forest
│   │   │   ├── gru.py                # Step 5: Pure-NumPy GRU (no framework needed)
│   │   │   ├── survival.py           # Step 6: Survival layer
│   │   │   ├── policy.py             # Step 7: WATCH / SHIELD / SUSPEND
│   │   │   ├── backup.py             # Backup manager
│   │   │   ├── training.py           # Train + evaluate the model stack
│   │   │   ├── simulator.py          # Synthetic training data generator
│   │   │   ├── attack_emulator.py    # Safe demo attack (sandbox only)
│   │   │   └── train.py              # CLI training entry point
│   │   └── db/database.py            # SQLite for decision log
│   ├── tests/                        # pytest suite
│   ├── requirements.txt
│   └── pyproject.toml
├── frontend/
│   └── src/
│       ├── App.tsx                   # Root — renders GuardianDashboard
│       ├── App.css                   # All design tokens + component styles
│       ├── services/api.ts           # Guardian API client
│       └── components/views/
│           └── GuardianDashboard.tsx # Single-page dashboard
├── sample_data/                      # Synthetic organisation profiles (legacy)
├── simulation/                       # Headless emulator helpers
├── run.sh                            # Quick-start commands
└── README.md
```

---

## Quickstart

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 1. Install Dependencies

**Backend:**
```bash
python -m pip install -r backend/requirements.txt
```

**Frontend:**
```bash
cd frontend
npm install
cd ..
```

### 2. Start Backend and Frontend

**Terminal 1 — FastAPI backend (http://localhost:8000):**
```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```
Swagger docs: http://localhost:8000/docs

**Terminal 2 — Vite dashboard (http://localhost:5173):**
```bash
cd frontend
npm run dev
```

Or use the helper script:
```bash
./run.sh server   # start backend
```

### 3. Using the Dashboard

1. **Create Demo Sandbox** — creates 400 dummy files in `backend/data/sandbox/`.
2. **Train Models** — trains the Isolation Forest and GRU (~2 minutes). Click once after a fresh install.
3. **Tick "I consent"** — required before monitoring starts.
4. **Start Guardian** — the 8-stage loop runs every second.
5. **Demo attack** — click `Attack: rename` to start a ransomware-like rename sweep on the sandbox files.
6. **Watch** the Risk, Survival Forecast, and Response panels respond in real time.
7. **Stop Demo / Stop Guardian** when done.

**To learn your computer's normal behaviour:**
Press **Learn My Behaviour**, use the folder normally for 10+ minutes, press Stop, then **Re-train Models** (keep "use my recorded baseline" ticked).

---

## Run Commands

```bash
./run.sh test      # Run pytest suite
./run.sh server    # Start backend
./run.sh train     # Train Guardian models from CLI (~2 min)
./run.sh demo      # Headless Guardian demo
./run.sh smoke     # HTTP smoke test
./run.sh generate  # Regenerate sample org profiles
```

---

## The 20 Features (Extracted Every Second)

| # | Feature | Description |
|---|---------|-------------|
| 0 | `create_count` | Files created this second |
| 1 | `modify_count` | Files modified |
| 2 | `delete_count` | Files deleted |
| 3 | `rename_count` | Files renamed / moved |
| 4 | `ext_change_count` | Renames that changed the file extension |
| 5 | `bytes_written` | Total bytes in modified/created files |
| 6 | `distinct_files` | Distinct files touched |
| 7 | `distinct_dirs` | Distinct folders touched |
| 8 | `mean_entropy` | Mean Shannon entropy of sampled files (0–8) |
| 9 | `max_entropy` | Maximum entropy seen |
| 10 | `high_entropy_ratio` | Fraction of files with entropy ≥ 7.2 |
| 11 | `entropy_jump_count` | Files whose entropy jumped from low → high |
| 12 | `canary_hits` | Decoy (canary) files touched |
| 13 | `backup_coverage` | Fraction of monitored files with a backup (0–1) |
| 14 | `unbacked_damaged` | Un-backed-up files modified/deleted/renamed |
| 15 | `top_proc_write_Bps` | Write rate of the busiest program (bytes/s) |
| 16 | `top_proc_read_Bps` | Read rate of that program |
| 17 | `rw_ratio` | Read/write ratio (0–4) |
| 18 | `n_writer_procs` | Number of programs writing right now |
| 19 | `event_count` | Total file events this second |

---

## Response Policy

| Action | Triggers |
|--------|----------|
| **WATCH** | No risk signs. Continue monitoring. |
| **SHIELD** | P(loss in 30 s) ≥ 25%, or P(loss in 10 s) ≥ 20%, or IF score ≥ 0.7 with risk signs, or canary file touched. Backs up at-risk files immediately. |
| **SUSPEND** | P(loss in 5 s) ≥ 50%, or P(loss in 10 s) ≥ 70%, or canary file encrypted/deleted, or time left < backup time needed. Pauses the offending program (after optional confirmation). |

SUSPEND never targets protected system processes or NitiQ itself.

---

## Honest Limitations

- The GRU and survival head are trained on **simulated** per-second behaviour (real ransomware logs are unsafe to collect). Reported metrics are on held-out simulated runs.
- The Isolation Forest is only as good as the baseline you record. With no recorded baseline it uses simulated normal behaviour, which may flag legitimate heavy I/O.
- Program attribution uses the busiest writer process; heavy unrelated programs can confuse it.
- The demo sandbox attack emulator only rewrites NitiQ's own dummy files inside the `.nitiq_sandbox` folder.

---

## Tests

```bash
python -m pytest backend/tests -v
```

All tests cover graph building, spread simulation, backup resilience, recovery time, scoring bounds, what-if overrides, baseline telemetry, privacy guarantees, Isolation Forest training, safe evaluation, and API endpoints.
