#!/usr/bin/env bash
# NitiQ - Local Run and Test Script

set -e

COMMAND="${1:-test}"

case "$COMMAND" in
  test)
    echo "Running NitiQ backend tests..."
    python -m pytest backend/tests -v
    ;;
  server)
    echo "Starting NitiQ FastAPI backend on http://127.0.0.1:8000..."
    python -m uvicorn backend.app.main:app --reload --port 8000
    ;;
  smoke)
    echo "Running live HTTP smoke test..."
    python backend/tests/smoke_test.py
    ;;
  train)
    echo "Training Guardian models (Isolation Forest + GRU survival)..."
    python -m backend.app.guardian.train --evaluate
    ;;
  demo)
    echo "Headless Guardian demo on the sandbox..."
    python backend/tests/guardian_demo.py
    ;;
  generate)
    echo "Regenerating sample organization profiles..."
    python -m backend.app.data.generate_profiles
    ;;
  *)
    echo "Usage: ./run.sh [test|server|smoke|train|demo|generate]"
    exit 1
    ;;
esac
