# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

import pytest

from canary_fabric.blast_radius_breaker import (
    BlastRadiusCircuitBreaker,
    BlastRadiusTrippedError,
)


def test_blast_radius_circuit_breaker_velocity_and_strikes() -> None:
    breaker = BlastRadiusCircuitBreaker(
        max_calls_per_window=3,
        window_seconds=10.0,
        max_security_strikes=2,
    )
    breaker.check_and_record_call("agent:alpha", now_s=1.0)
    breaker.check_and_record_call("agent:alpha", now_s=2.0)
    breaker.check_and_record_call("agent:alpha", now_s=3.0)
    with pytest.raises(BlastRadiusTrippedError, match="velocity_exceeded"):
        breaker.check_and_record_call("agent:alpha", now_s=4.0)

    breaker.check_and_record_call("agent:beta", has_injection_marker=True, now_s=4.0)
    with pytest.raises(BlastRadiusTrippedError, match="security_strikes_exceeded"):
        breaker.check_and_record_call("agent:beta", has_injection_marker=True, now_s=5.0)


def test_blast_radius_circuit_breaker_reset_and_sliding_window() -> None:
    breaker = BlastRadiusCircuitBreaker(
        max_calls_per_window=2,
        window_seconds=5.0,
        max_security_strikes=2,
    )
    breaker.check_and_record_call("agent:gamma", now_s=1.0)
    breaker.check_and_record_call("agent:gamma", now_s=2.0)

    # After sliding window expires (cutoff 7.0 - 5.0 = 2.0, so 1.0 and 2.0 are evicted)
    breaker.check_and_record_call("agent:gamma", now_s=7.0)
    breaker.check_and_record_call("agent:gamma", now_s=7.5)

    # 3rd call in window (7.0, 7.5, 7.8) exceeds max_calls=2
    with pytest.raises(BlastRadiusTrippedError, match="velocity_exceeded"):
        breaker.check_and_record_call("agent:gamma", now_s=7.8)

    # Agent is tripped and blocked on subsequent calls
    with pytest.raises(BlastRadiusTrippedError, match="circuit OPEN"):
        breaker.check_and_record_call("agent:gamma", now_s=8.0)

    # Reset agent clears state
    breaker.reset_agent("agent:gamma")
    breaker.check_and_record_call("agent:gamma", now_s=9.0)

    # Test monotonic fallback when now_s is None
    breaker.check_and_record_call("agent:delta")


def test_blast_radius_strike_sliding_window_and_cooldown() -> None:
    breaker = BlastRadiusCircuitBreaker(
        max_calls_per_window=10,
        window_seconds=10.0,
        max_security_strikes=2,
        strike_window_seconds=5.0,
        cooldown_seconds=10.0,
        agent_idle_ttl_s=20.0,
    )
    # Strike 1 at t=1.0
    breaker.check_and_record_call("agent:striker", has_injection_marker=True, now_s=1.0)

    # Strike 2 at t=7.0 (strike 1 at 1.0 is evicted because 7.0 - 5.0 = 2.0 > 1.0)
    breaker.check_and_record_call("agent:striker", has_injection_marker=True, now_s=7.0)

    # Strike 3 at t=8.0 (within 5s of t=7.0, so count reaches 2 -> trips)
    with pytest.raises(BlastRadiusTrippedError, match="security_strikes_exceeded"):
        breaker.check_and_record_call("agent:striker", has_injection_marker=True, now_s=8.0)

    # Circuit is OPEN before cooldown (t=12.0 < 8.0 + 10.0)
    with pytest.raises(BlastRadiusTrippedError, match="circuit OPEN"):
        breaker.check_and_record_call("agent:striker", now_s=12.0)

    # Cooldown expires at t=19.0 (>= 8.0 + 10.0), half-open probationary recovery succeeds
    breaker.check_and_record_call("agent:striker", now_s=19.0)


def test_blast_radius_idle_agent_pruning() -> None:
    breaker = BlastRadiusCircuitBreaker(
        agent_idle_ttl_s=10.0,
    )
    breaker.check_and_record_call("agent:ephemeral", now_s=1.0)
    assert "agent:ephemeral" in breaker._last_activity

    # At t=15.0, ephemeral agent is pruned
    breaker.check_and_record_call("agent:other", now_s=15.0)
    assert "agent:ephemeral" not in breaker._last_activity

    # Disabled pruning when agent_idle_ttl_s <= 0
    no_prune_breaker = BlastRadiusCircuitBreaker(agent_idle_ttl_s=0.0)
    no_prune_breaker.check_and_record_call("agent:stay", now_s=1.0)
    no_prune_breaker.check_and_record_call("agent:stay2", now_s=100.0)
    assert "agent:stay" in no_prune_breaker._last_activity
