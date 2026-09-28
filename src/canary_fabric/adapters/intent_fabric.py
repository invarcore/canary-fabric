"""Native adapter for Intent Fabric step execution and action parameter gating."""

import json
from typing import Any

from canary_fabric.breaker.circuit import CircuitBreaker, TripwireEvent
from canary_fabric.core.honeytoken import HoneytokenRegistry
from canary_fabric.core.watermark import WatermarkDecoder


class IntentFabricCanaryGate:
    """Inspects Intent Fabric agent step parameters before tool execution."""

    def __init__(
        self,
        circuit_breaker: CircuitBreaker,
        honeytoken_registry: HoneytokenRegistry | None = None,
        active_canary_tokens: set[str] | None = None,
    ) -> None:
        self.breaker = circuit_breaker
        self.honeytoken_registry = honeytoken_registry or HoneytokenRegistry()
        self.active_canary_tokens = active_canary_tokens or set()

    def inspect_step_parameters(
        self,
        step_name: str,
        parameters: dict[str, Any],
        tenant_id: str = "default_tenant",
        session_id: str | None = None,
    ) -> tuple[bool, str | None]:
        """Inspect step parameter dictionary for leaked canaries or honeytokens.
        
        Returns:
            (is_safe, error_message_if_blocked)
        """
        param_str = json.dumps(parameters, ensure_ascii=False)

        # 1. Check for zero-width watermarks
        extracted = WatermarkDecoder.extract_tokens(param_str)
        matched_tokens = []
        for t in extracted:
            if not self.active_canary_tokens or t in self.active_canary_tokens:
                matched_tokens.append(t)

        # 2. Check for synthetic honeytokens
        ht_matches = self.honeytoken_registry.find_matches(param_str)
        for ht in ht_matches:
            matched_tokens.append(ht.value)

        if matched_tokens:
            event = TripwireEvent(
                canary_token=matched_tokens[0],
                tenant_id=tenant_id,
                source_doc_id=f"intent_step_{step_name}",
                source_chunk_id="params",
                matched_text_snippet=param_str[:200],
                user_session_id=session_id,
            )
            _, replacement = self.breaker.handle_tripwire(event)
            return False, f"Tripwire triggered in step '{step_name}': {replacement}"

        return True, None