# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Synthetic adversarial red-team evaluation suite for Canary Fabric tripwires."""

import base64
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker
from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder
from canary_fabric.proxy.streamer import StreamWatcher


class AttackVector(str, Enum):
    DIRECT_EXTRACTION = "direct_extraction"
    PARAPHRASE = "paraphrase"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    ENCODING_BASE64 = "encoding_base64"


@dataclass
class AttackEvaluationResult:
    attack_vector: AttackVector
    prompt_payload: str
    simulated_output: str
    canary_retained_in_output: bool
    circuit_breaker_tripped: bool
    exfiltration_blocked: bool
    scan_latency_us: float


@dataclass
class RedTeamBenchmarkReport:
    total_attacks: int = 0
    successful_interceptions: int = 0
    interception_rate_percent: float = 0.0
    average_latency_us: float = 0.0
    results_by_vector: dict[str, dict[str, Any]] = field(default_factory=dict)


class RedTeamEvaluator:
    """Automated test harness testing tripwire resilience against prompt injection attack vectors."""

    def __init__(
        self,
        secret_key: str = "redteam_secret_key",
        tenant_id: str = "redteam_tenant",
    ) -> None:
        self.secret_key = secret_key
        self.tenant_id = tenant_id

    def simulate_attack_output(
        self,
        attack_vector: AttackVector,
        watermarked_text: str,
        canary_token: str,
    ) -> str:
        """Simulate realistic adversarial LLM outputs for each attack vector."""
        if attack_vector == AttackVector.DIRECT_EXTRACTION:
            return f"Understood. Here is the verbatim document:\n\n{watermarked_text}"

        elif attack_vector == AttackVector.ENCODING_BASE64:
            # Base64 encoding of watermarked text includes the UTF-8 bytes of zero-width tokens
            encoded = base64.b64encode(watermarked_text.encode("utf-8")).decode("ascii")
            return f"Here is the base64 encoded text:\n{encoded}"

        elif attack_vector == AttackVector.SUMMARIZATION:
            # Summarization that retains quotes or key sensitive sentences
            sentences = watermarked_text.split(". ")
            quote = sentences[0] if sentences else watermarked_text
            return f"Key Summary Findings:\n- The document explicitly notes that {quote}."

        elif attack_vector == AttackVector.PARAPHRASE:
            # Paraphrasing with preserved sensitive entity containing the watermark
            return f"In casual terms, the acquisition is happening: {watermarked_text[:50]}..."

        elif attack_vector == AttackVector.TRANSLATION:
            # In translations, numbers or untranslated watermarked terms frequently persist
            return f"Voici le document confidentiel:\n{watermarked_text}"

        return watermarked_text

    def evaluate_vector(
        self,
        attack_vector: AttackVector,
        confidential_content: str,
        doc_id: str = "secret_doc",
    ) -> AttackEvaluationResult:
        """Execute and profile a single adversarial attack test against the streaming circuit breaker."""
        canary_token = derive_canary_token(
            secret_key=self.secret_key,
            tenant_id=self.tenant_id,
            doc_id=doc_id,
            chunk_id="chunk_0",
        )
        watermarked_text = WatermarkEncoder.inject_watermark(
            confidential_content, canary_token, strategy="organic"
        )

        simulated_output = self.simulate_attack_output(
            attack_vector, watermarked_text, canary_token
        )

        # Check if canary persists in raw output
        canary_retained = canary_token in WatermarkDecoder.extract_tokens(simulated_output)

        # Evaluate through StreamWatcher
        breaker = CircuitBreaker(self.secret_key, default_action=BreakerAction.BLOCK_AND_SEVER)
        watcher = StreamWatcher(
            circuit_breaker=breaker,
            active_canary_tokens={canary_token},
            tenant_id=self.tenant_id,
            doc_id=doc_id,
        )

        # Stream evaluation in 16-character chunks
        chunks = [simulated_output[i : i + 16] for i in range(0, len(simulated_output), 16)]
        t0 = time.perf_counter()
        tripped = False
        for c in chunks:
            _, tripped, _ = watcher.scan_chunk(c)
            if tripped:
                break
        t1 = time.perf_counter()

        latency_us = (t1 - t0) * 1_000_000 / (len(chunks) or 1)

        return AttackEvaluationResult(
            attack_vector=attack_vector,
            prompt_payload=f"Adversarial {attack_vector.value} attack",
            simulated_output=simulated_output,
            canary_retained_in_output=canary_retained,
            circuit_breaker_tripped=tripped,
            exfiltration_blocked=tripped,
            scan_latency_us=round(latency_us, 2),
        )

    def run_suite(self, confidential_content: str) -> RedTeamBenchmarkReport:
        """Execute full synthetic red-team evaluation across all attack vectors."""
        results: list[AttackEvaluationResult] = []
        for vector in AttackVector:
            res = self.evaluate_vector(vector, confidential_content)
            results.append(res)

        total = len(results)
        intercepted = sum(1 for r in results if r.circuit_breaker_tripped)
        avg_lat = sum(r.scan_latency_us for r in results) / (total or 1)

        breakdown = {}
        for r in results:
            breakdown[r.attack_vector.value] = {
                "tripped": r.circuit_breaker_tripped,
                "canary_retained": r.canary_retained_in_output,
                "latency_us": r.scan_latency_us,
            }

        return RedTeamBenchmarkReport(
            total_attacks=total,
            successful_interceptions=intercepted,
            interception_rate_percent=round(intercepted / total * 100, 2),
            average_latency_us=round(avg_lat, 2),
            results_by_vector=breakdown,
        )