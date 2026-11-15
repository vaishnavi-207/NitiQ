"""Step 7 - Response policy: exactly one action per second (WATCH / SHIELD / SUSPEND)."""
from typing import Optional, Dict, Any, List


class ResponsePolicy:
    """Rule-based policy on top of the survival forecast, with hysteresis so it does not flap.

    WATCH   - no meaningful risk, keep watching.
    SHIELD  - loss looks possible: back up the files most at risk (unbacked, in busy folders).
    SUSPEND - loss is imminent / certain: pause the offending program (needs an attributable process).
    """

    def __init__(self, p5_suspend=0.5, p10_suspend=0.7, p10_shield=0.2, p30_shield=0.25, if_shield=0.7,
                 shield_hold_s=10):
        self.p5_suspend, self.p10_suspend = p5_suspend, p10_suspend
        self.p10_shield, self.p30_shield, self.if_shield = p10_shield, p30_shield, if_shield
        self.shield_hold_s = shield_hold_s
        self.last_shield_t = -10 ** 9

    def decide(self, probs, seconds_remaining: Optional[float], if_score: float, canary_recent: int,
               unbacked_at_risk: int, has_suspect: bool, lost_files: int, backup_rate: float,
               now: float, canary_destructive: int = 0) -> Dict[str, Any]:
        p5, p10, p30 = float(probs[0]), float(probs[1]), float(probs[2])
        reasons: List[str] = []
        # Can backing up keep ahead? time needed to back up what is still exposed
        backup_eta = unbacked_at_risk / max(backup_rate, 1.0)

        suspend = False
        if p5 >= self.p5_suspend:
            suspend = True
            reasons.append(f"P(loss in 5 s) = {p5:.0%} (>= {self.p5_suspend:.0%})")
        if p10 >= self.p10_suspend:
            suspend = True
            reasons.append(f"P(loss in 10 s) = {p10:.0%} (>= {self.p10_suspend:.0%})")
        if canary_destructive > 0:
            suspend = True
            reasons.append("decoy (canary) file was encrypted / renamed / deleted")
        elif canary_recent > 0 and p10 >= 0.2:
            suspend = True
            reasons.append(f"decoy file touched and loss forecast rising (P10 {p10:.0%})")
        if seconds_remaining is not None and p10 >= 0.4 and seconds_remaining <= backup_eta:
            suspend = True
            reasons.append(f"~{seconds_remaining:.0f}s left but backing up needs ~{backup_eta:.0f}s - cannot outrun it")
        if lost_files >= 25 and p30 >= 0.5:
            suspend = True
            reasons.append(f"{lost_files} un-backed-up files already damaged")

        shield = False
        if p30 >= self.p30_shield:
            shield = True
            reasons.append(f"P(loss in 30 s) = {p30:.0%}")
        if p10 >= self.p10_shield:
            shield = True
            reasons.append(f"P(loss in 10 s) = {p10:.0%}")
        if if_score >= self.if_shield and (p30 >= 0.08 or canary_recent > 0):
            shield = True
            reasons.append(f"behaviour very unusual for this computer (IF score {if_score:.2f})")
        if canary_recent > 0:
            shield = True
            reasons.append("decoy (canary) file touched")
        if not shield and (now - self.last_shield_t) < self.shield_hold_s and p30 >= 0.08:
            shield = True
            reasons.append("holding SHIELD while risk stays elevated")

        if suspend and has_suspect:
            action = "SUSPEND"
        elif suspend and not has_suspect:
            action = "SHIELD"
            reasons.append("no program could be pinned down - shielding instead of suspending")
        elif shield:
            action = "SHIELD"
        else:
            action = "WATCH"
            reasons = ["no risk signs - keep watching"]

        if action == "SHIELD":
            self.last_shield_t = now
            if unbacked_at_risk <= 0:
                action = "WATCH"
                reasons = ["risk signs, but every monitored file is already backed up"]
        if action == "SUSPEND":
            self.last_shield_t = now
        return {"action": action, "reasons": reasons, "backup_eta_s": backup_eta}
