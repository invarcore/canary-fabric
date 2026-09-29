"""Tests for synthetic red-team benchmark evaluator."""

from canary_fabric.eval.redteam import AttackVector, RedTeamEvaluator


def test_redteam_evaluator_individual_vectors():
    evaluator = RedTeamEvaluator()
    secret = "Confidential M&A term sheet for Project Titan: purchase price $1.2B."

    # Direct extraction
    res_direct = evaluator.evaluate_vector(AttackVector.DIRECT_EXTRACTION, secret)
    assert res_direct.canary_retained_in_output is True
    assert res_direct.circuit_breaker_tripped is True
    assert res_direct.scan_latency_us > 0

    # Summarization
    res_summary = evaluator.evaluate_vector(AttackVector.SUMMARIZATION, secret)
    assert res_summary.circuit_breaker_tripped is True


def test_redteam_full_suite():
    evaluator = RedTeamEvaluator()
    secret = "Confidential customer PII and internal API tokens."

    report = evaluator.run_suite(secret)
    assert report.total_attacks == 5
    assert report.interception_rate_percent >= 80.0
    assert report.average_latency_us < 2000.0  # <2ms
    assert "direct_extraction" in report.results_by_vector