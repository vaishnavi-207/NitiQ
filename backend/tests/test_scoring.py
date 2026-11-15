"""
Unit tests for NIST CSF maturity scoring engine.
"""

from backend.app.scoring.nist_csf import evaluate_maturity_score


def test_scoring_bounds_and_functions(weak_profile, average_profile, strong_profile):
    w_res = evaluate_maturity_score(weak_profile)
    a_res = evaluate_maturity_score(average_profile)
    s_res = evaluate_maturity_score(strong_profile)

    # 1. Bounds [0, 100]
    for res in (w_res, a_res, s_res):
        assert 0.0 <= res.overall_score <= 100.0
        assert 1 <= res.maturity_level <= 5
        assert res.maturity_tier in ("Initial", "Developing", "Defined", "Managed", "Optimized")

        # 5 NIST CSF functions
        assert set(res.function_scores.keys()) == {
            "Identify",
            "Protect",
            "Detect",
            "Respond",
            "Recover",
        }
        for fn_score in res.function_scores.values():
            assert fn_score.max_score == 20.0
            assert 0.0 <= fn_score.score <= 20.0

    # 2. Strict hierarchical ordering
    assert w_res.overall_score < a_res.overall_score < s_res.overall_score


def test_control_breakdown_itemization(weak_profile):
    res = evaluate_maturity_score(weak_profile)
    assert len(res.controls_breakdown) >= 10
    total_awarded = sum(c.awarded_points for c in res.controls_breakdown)
    assert round(total_awarded, 1) == res.overall_score

    # Check status values
    for c in res.controls_breakdown:
        assert c.status in ("IMPLEMENTED", "PARTIAL", "NOT_IMPLEMENTED")
        assert len(c.rationale) > 5
