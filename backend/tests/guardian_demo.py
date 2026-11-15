"""Headless demo: builds a sandbox, runs the Guardian, launches the safe emulator, prints each second."""
import sys
import time
from backend.app.guardian.engine import GUARDIAN
from backend.app.guardian.training import ModelStack, train_all

style = sys.argv[1] if len(sys.argv) > 1 else "rename"
rate = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
if not ModelStack.available():
    train_all(epochs=8)
GUARDIAN.prepare_sandbox(400, 0.4)
GUARDIAN.start("backend/data/sandbox", True, "guard", True)
time.sleep(8)
GUARDIAN.demo_attack(style, rate, 0)
for _ in range(25):
    time.sleep(1)
    s = GUARDIAN.state(); L = s["latest"]
    print(f"{L['tick']:3d} {L['action']:8s} IF={L['if_score']:.2f} P5={L['p5']:.2f} P10={L['p10']:.2f} P30={L['p30']:.2f} "
          f"left={L['seconds_remaining']} lost={s['lost_files']}/50 coverage={s['backup_coverage']:.0%} "
          f"paused={[x['name'] for x in s['suspended']]}")
GUARDIAN.demo_stop(); GUARDIAN.stop()
