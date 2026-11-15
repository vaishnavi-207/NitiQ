"""NitiQ Guardian - real-time ransomware time-to-loss detection loop.

Pipeline (runs once per second):
  1 System setup -> 2 Data collection -> 3 Feature extraction (20 numbers)
  -> 4 Isolation Forest (0-1 score) -> 5 GRU (10 x 21 window -> 64-number summary)
  -> 6 Survival layer (P(loss in 5/10/30 s), seconds remaining)
  -> 7 Response policy (WATCH / SHIELD / SUSPEND) -> 8 Dashboard + decision log
"""
