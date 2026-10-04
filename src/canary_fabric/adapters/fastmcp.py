# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""FastMCP Tool Decorator and Security Gate."""

import functools
import inspect
import json
from collections.abc import Callable
from typing import Any

from canary_fabric.breaker.circuit import CircuitBreaker, TripwireEvent
from canary_fabric.core.honeytoken import HoneytokenRegistry
from canary_fabric.core.watermark import WatermarkDecoder


def canary_gate(
    circuit_breaker: CircuitBreaker,
    honeytoken_registry: HoneytokenRegistry | None = None,
    active_canary_tokens: set[str] | None = None,
    tenant_id: str = "default_tenant",
) -> Callable:
    """Decorator to protect FastMCP / Python tool calls from data-leak exfiltration."""
    ht_reg = honeytoken_registry or HoneytokenRegistry()
    active_tokens = active_canary_tokens or set()

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Check inputs
            combined_args = json.dumps(
                {"args": args, "kwargs": kwargs}, default=str, ensure_ascii=False
            )
            extracted = WatermarkDecoder.extract_tokens(combined_args)
            matched = [t for t in extracted if not active_tokens or t in active_tokens]

            ht_matches = ht_reg.find_matches(combined_args)
            for ht in ht_matches:
                matched.append(ht.value)

            if matched:
                event = TripwireEvent(
                    canary_token=matched[0],
                    tenant_id=tenant_id,
                    source_doc_id=f"mcp_tool_{func.__name__}",
                    source_chunk_id="input_args",
                    matched_text_snippet=combined_args[:150],
                )
                _, replacement = circuit_breaker.handle_tripwire(event)
                raise PermissionError(f"CanaryFabric security tripwire triggered: {replacement}")

            # Execute tool
            result = func(*args, **kwargs)

            # Check output
            res_str = json.dumps(result, default=str, ensure_ascii=False)
            extracted_out = WatermarkDecoder.extract_tokens(res_str)
            matched_out = [t for t in extracted_out if not active_tokens or t in active_tokens]

            ht_matches_out = ht_reg.find_matches(res_str)
            for ht in ht_matches_out:
                matched_out.append(ht.value)

            if matched_out:
                event = TripwireEvent(
                    canary_token=matched_out[0],
                    tenant_id=tenant_id,
                    source_doc_id=f"mcp_tool_{func.__name__}",
                    source_chunk_id="output_result",
                    matched_text_snippet=res_str[:150],
                )
                _, replacement = circuit_breaker.handle_tripwire(event)
                return {"error": "TRIPWIRE_TRIGGERED", "details": replacement}

            return result

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            combined_args = json.dumps(
                {"args": args, "kwargs": kwargs}, default=str, ensure_ascii=False
            )
            extracted = WatermarkDecoder.extract_tokens(combined_args)
            matched = [t for t in extracted if not active_tokens or t in active_tokens]

            ht_matches = ht_reg.find_matches(combined_args)
            for ht in ht_matches:
                matched.append(ht.value)

            if matched:
                event = TripwireEvent(
                    canary_token=matched[0],
                    tenant_id=tenant_id,
                    source_doc_id=f"mcp_tool_{func.__name__}",
                    source_chunk_id="input_args",
                    matched_text_snippet=combined_args[:150],
                )
                _, replacement = circuit_breaker.handle_tripwire(event)
                raise PermissionError(f"CanaryFabric security tripwire triggered: {replacement}")

            result = await func(*args, **kwargs)

            res_str = json.dumps(result, default=str, ensure_ascii=False)
            extracted_out = WatermarkDecoder.extract_tokens(res_str)
            matched_out = [t for t in extracted_out if not active_tokens or t in active_tokens]

            ht_matches_out = ht_reg.find_matches(res_str)
            for ht in ht_matches_out:
                matched_out.append(ht.value)

            if matched_out:
                event = TripwireEvent(
                    canary_token=matched_out[0],
                    tenant_id=tenant_id,
                    source_doc_id=f"mcp_tool_{func.__name__}",
                    source_chunk_id="output_result",
                    matched_text_snippet=res_str[:150],
                )
                _, replacement = circuit_breaker.handle_tripwire(event)
                return {"error": "TRIPWIRE_TRIGGERED", "details": replacement}

            return result

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
