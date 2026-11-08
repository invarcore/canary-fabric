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
    ) -> None:
        self._max_calls = max_calls_per_window
        self._window_s = window_seconds
        self._max_strikes = max_security_strikes
        self._call_timestamps: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self._strikes: Dict[str, int] = collections.defaultdict(int)
        self._tripped_reason: Dict[str, str] = {}
        self._lock = threading.Lock()

    def check_and_record_call(
        self,
        agent_id: str,
        has_injection_marker: bool = False,
        now_s: Optional[float] = None,
    ) -> None:
        norm_agent = unicodedata.normalize("NFC", agent_id).strip()
        ts = float(now_s if now_s is not None else time.monotonic())
        with self._lock:
            if norm_agent in self._tripped_reason:
                raise BlastRadiusTrippedError(
                    f"ASI08 circuit OPEN for '{norm_agent}': {self._tripped_reason[norm_agent]}"
                )

            if has_injection_marker:
                self._strikes[norm_agent] += 1
                if operator.ge(self._strikes[norm_agent], self._max_strikes):
                    reason = f"security_strikes_exceeded ({self._strikes[norm_agent]})"
                    self._tripped_reason[norm_agent] = reason
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
                raise BlastRadiusTrippedError(f"ASI08 circuit OPEN for '{norm_agent}': {reason}")

    def reset_agent(self, agent_id: str) -> None:
        norm_agent = unicodedata.normalize("NFC", agent_id).strip()
        with self._lock:
            self._tripped_reason.pop(norm_agent, None)
            self._strikes.pop(norm_agent, None)
            self._call_timestamps.pop(norm_agent, None)
