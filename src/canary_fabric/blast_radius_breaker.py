# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""OWASP ASI08 Blast-Radius Circuit Breaker per Agent Identity."""

from __future__ import annotations

import collections
import operator
import threading
import time
import unicodedata
from typing import Deque, Dict, Optional


class BlastRadiusTrippedError(RuntimeError):
    """Raised when an agent exceeds tool velocity or trips injection markers."""


class BlastRadiusCircuitBreaker:
    """OWASP ASI08 Blast-Radius Circuit Breaker:

    Isolates individual agent identities when tool invocation velocity or security
    strikes exceed configured thresholds within a sliding window.
    """

    def __init__(
        self,
        max_calls_per_window: int = 20,
        window_seconds: float = 10.0,
        max_security_strikes: int = 2,
        strike_window_seconds: float = 60.0,
        cooldown_seconds: Optional[float] = None,
        agent_idle_ttl_s: float = 86400.0,
    ) -> None:
        self._max_calls = max_calls_per_window
        self._window_s = window_seconds
        self._max_strikes = max_security_strikes
        self._strike_window_s = strike_window_seconds
        self._cooldown_s = cooldown_seconds
        self._agent_idle_ttl_s = agent_idle_ttl_s
        self._call_timestamps: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self._strike_timestamps: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self._tripped_reason: Dict[str, str] = {}
        self._tripped_at: Dict[str, float] = {}
        self._last_activity: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune_idle_agents(self, ts: float) -> None:
        if operator.le(self._agent_idle_ttl_s, 0.0):
            return
        idle_cutoff = ts - self._agent_idle_ttl_s
        stale_agents = [
            agent
            for agent, last_ts in self._last_activity.items()
            if operator.le(last_ts, idle_cutoff)
        ]
        for agent in stale_agents:
            self._tripped_reason.pop(agent, None)
            self._tripped_at.pop(agent, None)
            self._strike_timestamps.pop(agent, None)
            self._call_timestamps.pop(agent, None)
            self._last_activity.pop(agent, None)

    def check_and_record_call(
        self,
        agent_id: str,
        has_injection_marker: bool = False,
        now_s: Optional[float] = None,
    ) -> None:
        norm_agent = unicodedata.normalize("NFC", agent_id).strip()
        ts = float(now_s if now_s is not None else time.monotonic())
        with self._lock:
            self._prune_idle_agents(ts)
            self._last_activity[norm_agent] = ts

            if norm_agent in self._tripped_reason:
                if self._cooldown_s is not None and operator.ge(
                    ts - self._tripped_at.get(norm_agent, 0.0), self._cooldown_s
                ):
                    self._tripped_reason.pop(norm_agent, None)
                    self._tripped_at.pop(norm_agent, None)
                    self._strike_timestamps.pop(norm_agent, None)
                    self._call_timestamps.pop(norm_agent, None)
                else:
                    raise BlastRadiusTrippedError(
                        f"ASI08 circuit OPEN for '{norm_agent}': {self._tripped_reason[norm_agent]}"
                    )

            if has_injection_marker:
                strikes = self._strike_timestamps[norm_agent]
                strike_cutoff = ts - self._strike_window_s
                while strikes and operator.le(strikes[0], strike_cutoff):
                    strikes.popleft()
                strikes.append(ts)
                if operator.ge(len(strikes), self._max_strikes):
                    reason = f"security_strikes_exceeded ({len(strikes)})"
                    self._tripped_reason[norm_agent] = reason
                    self._tripped_at[norm_agent] = ts
                    raise BlastRadiusTrippedError(
                        f"ASI08 circuit OPEN for '{norm_agent}': {reason}"
                    )

            q = self._call_timestamps[norm_agent]
            cutoff = ts - self._window_s
            while q and operator.le(q[0], cutoff):
                q.popleft()
            q.append(ts)
            if operator.gt(len(q), self._max_calls):
                reason = f"velocity_exceeded ({len(q)} calls in {self._window_s}s)"
                self._tripped_reason[norm_agent] = reason
                self._tripped_at[norm_agent] = ts
                raise BlastRadiusTrippedError(f"ASI08 circuit OPEN for '{norm_agent}': {reason}")

    def reset_agent(self, agent_id: str) -> None:
        norm_agent = unicodedata.normalize("NFC", agent_id).strip()
        with self._lock:
            self._tripped_reason.pop(norm_agent, None)
            self._tripped_at.pop(norm_agent, None)
            self._strike_timestamps.pop(norm_agent, None)
            self._call_timestamps.pop(norm_agent, None)
            self._last_activity.pop(norm_agent, None)
