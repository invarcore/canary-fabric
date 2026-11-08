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
