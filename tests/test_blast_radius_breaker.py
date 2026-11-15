import pytest

from canary_fabric.blast_radius_breaker import (
    BlastRadiusCircuitBreaker,
    BlastRadiusTrippedError,
    BreakerState,
)


def test_sliding_window_strike_decay_and_isolation():
    clock = [100.0]
    breaker = BlastRadiusCircuitBreaker(
        window_seconds=60.0,
        max_strikes=3.0,
        max_invocations_per_window=10,
        cooldown_seconds=120.0,
        now_fn=lambda: clock[0],
    )

    # 2 strikes at t=100s -> stays CLOSED
    d1 = breaker.record_and_check("agent-1", anomaly_weight=2.0, reason="suspicious_fetch")
    assert d1.state == BreakerState.CLOSED
    assert d1.active_strikes == 2.0

    # Advance 65s past window -> first 2 strikes decay to 0
    clock[0] = 165.0
    d2 = breaker.record_and_check("agent-1", anomaly_weight=2.0, reason="second_fetch")
    assert d2.active_strikes == 2.0

    # Immediate +1.5 strike within window -> 3.5 >= 3.0 -> trips OPEN
    clock[0] = 170.0
    with pytest.raises(BlastRadiusTrippedError, match=r"strikes=3\.5/3\.0"):
        breaker.record_and_check("agent-1", anomaly_weight=1.5, reason="canary_echo")

    # Subsequent benign call during 120s cooldown is rejected immediately, while agent-2 is unaffected
    with pytest.raises(BlastRadiusTrippedError, match="isolated in OPEN state"):
        breaker.record_and_check("agent-1", anomaly_weight=0.0)

    assert breaker.record_and_check("agent-2", anomaly_weight=0.0).state == BreakerState.CLOSED


def test_velocity_cap_trips_on_runaway_chaining():
    clock = [10.0]
    breaker = BlastRadiusCircuitBreaker(
        window_seconds=30.0, max_strikes=5.0, max_invocations_per_window=3, now_fn=lambda: clock[0]
    )
    for _ in range(3):
        breaker.record_and_check("runaway-agent")
    with pytest.raises(BlastRadiusTrippedError, match="velocity=4/3"):
        breaker.record_and_check("runaway-agent")


def test_validation_errors():
    with pytest.raises(ValueError, match="Breaker thresholds and window_seconds must be positive"):
        BlastRadiusCircuitBreaker(window_seconds=0.0)
    with pytest.raises(ValueError, match="Breaker thresholds and window_seconds must be positive"):
        BlastRadiusCircuitBreaker(max_strikes=0.0)
    with pytest.raises(ValueError, match="Breaker thresholds and window_seconds must be positive"):
        BlastRadiusCircuitBreaker(max_invocations_per_window=0)

    breaker = BlastRadiusCircuitBreaker()
    with pytest.raises(ValueError, match="agent_id is mandatory"):
        breaker.record_and_check("")
    with pytest.raises(ValueError, match="agent_id is mandatory"):
        breaker.record_and_check("   ")
