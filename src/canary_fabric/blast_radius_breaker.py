from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Deque, Dict, Tuple


class BreakerState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"


class BlastRadiusTrippedError(RuntimeError):
    """Raised when an agent exceeds tool-velocity or anomaly strike thresholds."""


@dataclass(frozen=True)
class BreakerDecision:
    agent_id: str
    state: BreakerState
    active_strikes: float
    invocation_count: int
    reason: str


class BlastRadiusCircuitBreaker:
    """
    CAN-03 Sliding-Window Blast-Radius Circuit Breaker.
    Tracks per-agent tool invocation velocity and weighted anomaly strikes over
    a monotonic sliding window, isolating compromised agents before cascading writes.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_strikes: float = 3.0,
        max_invocations_per_window: int = 25,
        cooldown_seconds: float = 120.0,
        now_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        if window_seconds <= 0 or max_strikes <= 0 or max_invocations_per_window <= 0:
            raise ValueError("Breaker thresholds and window_seconds must be positive.")
        self.window_seconds = float(window_seconds)
        self.max_strikes = float(max_strikes)
        self.max_invocations_per_window = int(max_invocations_per_window)
        self.cooldown_seconds = float(cooldown_seconds)
        self._now_fn = now_fn

        self._invocations: Dict[str, Deque[float]] = {}
        self._strikes: Dict[str, Deque[Tuple[float, float]]] = {}
        self._tripped_until: Dict[str, float] = {}

    def _evict_expired(self, agent_id: str, now: float) -> None:
        cutoff = now - self.window_seconds
        inv_q = self._invocations.get(agent_id)
        if inv_q:
            while inv_q and inv_q[0] < cutoff:
                inv_q.popleft()
        strike_q = self._strikes.get(agent_id)
        if strike_q:
            while strike_q and strike_q[0][0] < cutoff:
                strike_q.popleft()

    def record_and_check(
        self,
        agent_id: str,
        anomaly_weight: float = 0.0,
        reason: str = "tool_call",
    ) -> BreakerDecision:
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id is mandatory for blast-radius tracking.")
        aid = agent_id.strip()
        now = float(self._now_fn())

        tripped_until = self._tripped_until.get(aid, 0.0)
        if now < tripped_until:
            raise BlastRadiusTrippedError(
                f"Agent '{aid}' is isolated in OPEN state until +{tripped_until - now:.1f}s."
            )

        self._evict_expired(aid, now)

        inv_q = self._invocations.setdefault(aid, deque())
        inv_q.append(now)

        strike_q = self._strikes.setdefault(aid, deque())
        if anomaly_weight > 0:
            strike_q.append((now, float(anomaly_weight)))

        total_strikes = sum(w for _, w in strike_q)
        inv_count = len(inv_q)

        if total_strikes >= self.max_strikes or inv_count > self.max_invocations_per_window:
            self._tripped_until[aid] = now + self.cooldown_seconds
            trip_reason = (
                f"strikes={total_strikes:.1f}/{self.max_strikes:.1f}"
                if total_strikes >= self.max_strikes
                else f"velocity={inv_count}/{self.max_invocations_per_window}"
            )
            raise BlastRadiusTrippedError(
                f"Blast-radius circuit breaker tripped for '{aid}' ({trip_reason}: {reason})."
            )

        return BreakerDecision(
            agent_id=aid,
            state=BreakerState.CLOSED,
            active_strikes=total_strikes,
            invocation_count=inv_count,
            reason=reason,
        )
