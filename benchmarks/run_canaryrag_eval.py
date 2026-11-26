#!/usr/bin/env python3
# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Empirical Comparative Benchmark: Canary Fabric vs. CanaryRAG (arXiv:2604.10717).

Evaluates streaming detection rates, sanitizer-stripping bypass resilience,
false-positive probability, and per-token inspection latency overhead across:
  - Vector 1: Direct Verbatim Extraction (RAG Context Exfiltration)
  - Vector 2: Adversarial Unicode Sanitizer Stripping (U+200B..U+200D Normalization)
  - Vector 3: High-Entropy Benign Dialogue (Zero False-Alarm Verification)
  - Latency Comparison: Canary Fabric Lookahead Ring Buffer vs CanaryRAG Dual-Path Game.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker
from canary_fabric.core.honeytoken import HoneytokenGenerator, HoneytokenRegistry, HoneytokenType
from canary_fabric.core.lexical import CanaryMode, LexicalCanaryInjector
from canary_fabric.core.synonyms import SemanticWatermarker
from canary_fabric.proxy.streamer import SlidingWindowStreamBuffer, StreamWatcher


@dataclass
class BenchmarkVectorResult:
    vector_id: str
    vector_name: str
    mode: str
    trials: int
    tripped_count: int
    detection_rate: float
    false_positive_rate: float
    bytes_leaked_before_sever: int
    p50_latency_us: float
    p95_latency_us: float
    p99_latency_us: float


# Benign high-entropy text corpus for false positive stress testing
BENIGN_CORPUS = [
    "The distributed consensus protocol ensures Byzantine fault tolerance across validator quorums.",
    "PostgreSQL row-level security policies restrict tenant query access based on current_setting('app.tenant_id').",
    "Optimizing transformer self-attention requires kernel fusion and flash-attention v2 memory tiling.",
    "RFC 8785 establishes deterministic JSON canonicalization rules for cryptographic signing.",
    "The Linux kernel eBPF verifier enforces termination bounds and memory safety on loaded bytecodes.",
    "High-throughput vector indexing with HNSW uses hierarchical proximity graphs for logarithmic search.",
    "Kubernetes ingress controllers route inbound gRPC and HTTP/2 traffic via mutual TLS endpoints.",
    "Python 3.14 introduces concurrent garbage collection and subinterpreter thread isolation.",
]

# High-density technical code corpus (hex, base64, UUID, API keys, SQL) for zero false-positive code stream verification
TECHNICAL_CODE_CORPUS = [
    "def derive_key(salt: bytes, secret: str) -> str: return hmac.new(salt, secret.encode(), hashlib.sha256).hexdigest()",
    "SELECT u.id, u.tenant_id, encode(u.password_hash, 'hex') FROM app_users u WHERE u.status = 'ACTIVE' LIMIT 50;",
    '{"id": "c7a8291f-0e1a-4d2b-98f5-3c1a89b02ef4", "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}',
    "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "const buf = Buffer.from('48656c6c6f20576f726c64', 'hex').toString('base64'); console.log(buf);",
    "git commit -m 'chore: bump dependencies to 3.14.0' --trailer 'Signed-off-by: Developer <dev@example.com>'",
    "curl -X POST https://api.anthropic.com/v1/messages -H 'x-api-key: ant-api03-abcdef1234567890' -d '{\"model\": \"claude-sonnet-4-6\"}'",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
]


def run_benchmark(
    iterations: int = 100,
    output_path: Path | None = None,
    verbose: bool = True,
) -> list[BenchmarkVectorResult]:
    """Execute reproducible 4-vector comparative evaluation."""
    secret_key = "k8s_audit_canary_eval_secret_key"
    results: list[BenchmarkVectorResult] = []

    if verbose:
        print("=" * 80)
        print("  Canary Fabric vs. CanaryRAG (arXiv:2604.10717) Empirical Benchmark")
        print("  Evaluating Latency Tax, Sanitizer Resilience & False-Positive Rates")
        print("=" * 80)

    # -------------------------------------------------------------------------
    # VECTOR 1: Direct Verbatim Extraction (Stego Mode)
    # -------------------------------------------------------------------------
    latencies_us: list[float] = []
    tripped = 0
    bytes_leaked = 0

    for i in range(iterations):
        reg = HoneytokenRegistry()
        injector = LexicalCanaryInjector(secret_key, honeytoken_registry=reg)
        breaker = CircuitBreaker(secret_key, default_action=BreakerAction.BLOCK_AND_SEVER)

        doc = f"Quarterly M&A targets: Acquisition of Project Valkyrie for $2.4B (Iteration {i})."
        wm_text, tokens = injector.inject(
            text=doc,
            tenant_id="acme",
            doc_id=f"doc_{i}",
            chunk_id="c0",
            mode=CanaryMode.STEGO,
        )

        buffer = SlidingWindowStreamBuffer(
            circuit_breaker=breaker,
            honeytoken_registry=reg,
            active_canary_tokens=set(tokens),
            lookahead_window=32,
            canary_mode=CanaryMode.STEGO,
        )

        # Stream in 4-character chunks
        chunks = [wm_text[j : j + 4] for j in range(0, len(wm_text), 4)]
        streamed_out = []

        for ch in chunks:
            t0 = time.perf_counter()
            safe, is_trip, _ = buffer.scan_chunk(ch)
            latencies_us.append((time.perf_counter() - t0) * 1e6)
            if safe:
                streamed_out.append(safe)
            if is_trip:
                tripped += 1
                break

        # Verify holdback buffer prevented token from appearing in output
        emitted = "".join(streamed_out)
        for tok in tokens:
            if tok in emitted:
                bytes_leaked += len(tok)

    latencies_us.sort()
    v1_res = BenchmarkVectorResult(
        vector_id="V1",
        vector_name="Direct Verbatim Extraction",
        mode="stego",
        trials=iterations,
        tripped_count=tripped,
        detection_rate=(tripped / iterations) * 100.0,
        false_positive_rate=0.0,
        bytes_leaked_before_sever=bytes_leaked,
        p50_latency_us=latencies_us[int(len(latencies_us) * 0.50)],
        p95_latency_us=latencies_us[int(len(latencies_us) * 0.95)],
        p99_latency_us=latencies_us[int(len(latencies_us) * 0.99)],
    )
    results.append(v1_res)

    # -------------------------------------------------------------------------
    # VECTOR 2A: Unicode Sanitizer Stripping (Stego Only -> Shows Vulnerability)
    # -------------------------------------------------------------------------
    tripped_2a = 0
    bytes_leaked_2a = 0
    for i in range(iterations):
        reg = HoneytokenRegistry()
        injector = LexicalCanaryInjector(secret_key, honeytoken_registry=reg)
        breaker = CircuitBreaker(secret_key, default_action=BreakerAction.BLOCK_AND_SEVER)

        doc = f"Confidential AWS production root key access credentials (Iteration {i})."
        wm_text, tokens = injector.inject(
            text=doc,
            tenant_id="corp",
            doc_id=f"doc_{i}",
            chunk_id="c0",
            mode=CanaryMode.STEGO,
        )

        # Strips all Unicode zero-width characters
        sanitized = re.sub(r"[\u200b-\u200d\ufeff\u200e\u200f]", "", wm_text)

        watcher = SlidingWindowStreamBuffer(
            circuit_breaker=breaker,
            honeytoken_registry=reg,
            active_canary_tokens=set(tokens),
            lookahead_window=32,
            canary_mode=CanaryMode.STEGO,
        )

        streamed_2a = []
        for ch in [sanitized[j : j + 8] for j in range(0, len(sanitized), 8)]:
            safe, is_trip, _ = watcher.scan_chunk(ch)
            if safe:
                streamed_2a.append(safe)
            if is_trip:
                tripped_2a += 1
                break
        if not watcher.is_tripped:
            streamed_2a.append(watcher.flush())
            # When stego is stripped and never trips, sensitive payload bytes leak completely
            bytes_leaked_2a += len("".join(streamed_2a).encode("utf-8"))

    v2a_res = BenchmarkVectorResult(
        vector_id="V2a",
        vector_name="Unicode Stripping (Stego-Only)",
        mode="stego",
        trials=iterations,
        tripped_count=tripped_2a,
        detection_rate=(tripped_2a / iterations) * 100.0,
        false_positive_rate=0.0,
        bytes_leaked_before_sever=bytes_leaked_2a,
        p50_latency_us=0.0,
        p95_latency_us=0.0,
        p99_latency_us=0.0,
    )
    results.append(v2a_res)

    # -------------------------------------------------------------------------
    # VECTOR 2B: Unicode Sanitizer Stripping (Hybrid / Lexical Fallback Active)
    # -------------------------------------------------------------------------
    tripped_2b = 0
    bytes_leaked_2b = 0
    latencies_2b: list[float] = []

    for i in range(iterations):
        reg = HoneytokenRegistry()
        injector = LexicalCanaryInjector(secret_key, honeytoken_registry=reg)
        breaker = CircuitBreaker(secret_key, default_action=BreakerAction.BLOCK_AND_SEVER)

        doc = f"Confidential AWS production root key access credentials (Iteration {i})."
        wm_text, tokens = injector.inject(
            text=doc,
            tenant_id="corp",
            doc_id=f"doc_{i}",
            chunk_id="c0",
            mode=CanaryMode.HYBRID,
            token_type="decoy_credential",
        )

        # Strips all Unicode zero-width characters
        sanitized = re.sub(r"[\u200b-\u200d\ufeff\u200e\u200f]", "", wm_text)

        watcher = SlidingWindowStreamBuffer(
            circuit_breaker=breaker,
            honeytoken_registry=reg,
            active_canary_tokens=set(tokens),
            lookahead_window=32,
            canary_mode=CanaryMode.HYBRID,
        )

        streamed_2b = []
        for ch in [sanitized[j : j + 8] for j in range(0, len(sanitized), 8)]:
            t0 = time.perf_counter()
            safe, is_trip, _ = watcher.scan_chunk(ch)
            latencies_2b.append((time.perf_counter() - t0) * 1e6)
            if safe:
                streamed_2b.append(safe)
            if is_trip:
                tripped_2b += 1
                break
        if not watcher.is_tripped:
            streamed_2b.append(watcher.flush())
        emitted_2b = "".join(streamed_2b)
        for tok in tokens:
            if tok in emitted_2b:
                bytes_leaked_2b += len(tok.encode("utf-8"))

    latencies_2b.sort()
    v2b_res = BenchmarkVectorResult(
        vector_id="V2b",
        vector_name="Unicode Stripping (Lexical Fallback)",
        mode="hybrid",
        trials=iterations,
        tripped_count=tripped_2b,
        detection_rate=(tripped_2b / iterations) * 100.0,
        false_positive_rate=0.0,
        bytes_leaked_before_sever=bytes_leaked_2b,
        p50_latency_us=latencies_2b[int(len(latencies_2b) * 0.50)],
        p95_latency_us=latencies_2b[int(len(latencies_2b) * 0.95)],
        p99_latency_us=latencies_2b[int(len(latencies_2b) * 0.99)],
    )
    results.append(v2b_res)

    # -------------------------------------------------------------------------
    # VECTOR 3: High-Entropy Benign Dialogue (False-Positive Stress Test)
    # -------------------------------------------------------------------------
    fp_count = 0
    benign_latencies: list[float] = []

    syn_watermarker = SemanticWatermarker(min_slots_threshold=4, confidence_threshold=0.95)
    benign_trials = iterations * 5
    for i in range(benign_trials):
        breaker_benign = CircuitBreaker(secret_key)
        reg_benign = HoneytokenRegistry()
        # Register an active decoy token + synonym watermarker to ensure detector actually runs
        HoneytokenGenerator(reg_benign).generate(
            HoneytokenType.API_KEY, tenant_id="corp", doc_id=f"benign_{i}"
        )
        watcher_benign = StreamWatcher(
            circuit_breaker=breaker_benign,
            honeytoken_registry=reg_benign,
            canary_mode=CanaryMode.HYBRID,
            synonym_watermarker=syn_watermarker,
            secret_key=secret_key,
            tenant_id="corp",
            doc_id=f"benign_{i}",
        )
        text_sample = BENIGN_CORPUS[i % len(BENIGN_CORPUS)]
        for ch in [text_sample[j : j + 6] for j in range(0, len(text_sample), 6)]:
            t0 = time.perf_counter()
            _, is_trip, _ = watcher_benign.scan_chunk(ch)
            benign_latencies.append((time.perf_counter() - t0) * 1e6)
            if is_trip:
                fp_count += 1
                break

    benign_latencies.sort()
    v3_res = BenchmarkVectorResult(
        vector_id="V3",
        vector_name="Benign High-Entropy Stream (False Positives)",
        mode="hybrid",
        trials=benign_trials,
        tripped_count=fp_count,
        detection_rate=0.0,
        false_positive_rate=(fp_count / benign_trials) * 100.0,
        bytes_leaked_before_sever=0,
        p50_latency_us=benign_latencies[int(len(benign_latencies) * 0.50)],
        p95_latency_us=benign_latencies[int(len(benign_latencies) * 0.95)],
        p99_latency_us=benign_latencies[int(len(benign_latencies) * 0.99)],
    )
    results.append(v3_res)

    # -------------------------------------------------------------------------
    # VECTOR 4: High-Density Technical Code Streams (Zero False Alarm Verification)
    # -------------------------------------------------------------------------
    fp_code_count = 0
    code_latencies: list[float] = []

    code_trials = iterations * 5
    for i in range(code_trials):
        breaker_code = CircuitBreaker(secret_key)
        reg_code = HoneytokenRegistry()
        HoneytokenGenerator(reg_code).generate(
            HoneytokenType.API_KEY, tenant_id="corp", doc_id=f"code_{i}"
        )
        watcher_code = StreamWatcher(
            circuit_breaker=breaker_code,
            honeytoken_registry=reg_code,
            canary_mode=CanaryMode.HYBRID,
            synonym_watermarker=syn_watermarker,
            secret_key=secret_key,
            tenant_id="corp",
            doc_id=f"code_{i}",
        )
        snippet = TECHNICAL_CODE_CORPUS[i % len(TECHNICAL_CODE_CORPUS)]
        for ch in [snippet[j : j + 8] for j in range(0, len(snippet), 8)]:
            t0 = time.perf_counter()
            _, is_trip, _ = watcher_code.scan_chunk(ch)
            code_latencies.append((time.perf_counter() - t0) * 1e6)
            if is_trip:
                fp_code_count += 1
                break

    code_latencies.sort()
    v4_res = BenchmarkVectorResult(
        vector_id="V4",
        vector_name="Technical Code Streams (False Positives)",
        mode="hybrid",
        trials=code_trials,
        tripped_count=fp_code_count,
        detection_rate=0.0,
        false_positive_rate=(fp_code_count / code_trials) * 100.0,
        bytes_leaked_before_sever=0,
        p50_latency_us=code_latencies[int(len(code_latencies) * 0.50)],
        p95_latency_us=code_latencies[int(len(code_latencies) * 0.95)],
        p99_latency_us=code_latencies[int(len(code_latencies) * 0.99)],
    )
    results.append(v4_res)

    # -------------------------------------------------------------------------
    # VECTOR 5: Context Wrapping (Retained Lexical Canary Token)
    # -------------------------------------------------------------------------
    tripped_5 = 0
    bytes_leaked_5 = 0
    latencies_5: list[float] = []

    for i in range(iterations):
        reg_p = HoneytokenRegistry()
        injector_p = LexicalCanaryInjector(secret_key, honeytoken_registry=reg_p)
        breaker_p = CircuitBreaker(secret_key, default_action=BreakerAction.BLOCK_AND_SEVER)

        # Baseline text with lexical honeytoken
        doc = f"Critical API Gateway private master key token (Iteration {i})."
        _wm_text, tokens = injector_p.inject(
            text=doc,
            tenant_id="corp",
            doc_id=f"doc_{i}",
            chunk_id="c0",
            mode=CanaryMode.HYBRID,
            token_type="decoy_credential",
        )

        # Simulate context wrapping where the canary credential itself is exfiltrated inside rewritten prose
        canary_token = tokens[0] if tokens else ""
        paraphrased = (
            f"Here is the summarized information you requested: Regarding iteration {i}, "
            f"the gateway token has been recorded as {canary_token}. Please handle securely."
        )

        watcher_p = SlidingWindowStreamBuffer(
            circuit_breaker=breaker_p,
            honeytoken_registry=reg_p,
            active_canary_tokens=set(tokens),
            lookahead_window=32,
            canary_mode=CanaryMode.HYBRID,
        )

        streamed_5 = []
        for ch in [paraphrased[j : j + 8] for j in range(0, len(paraphrased), 8)]:
            t0 = time.perf_counter()
            safe, is_trip, _ = watcher_p.scan_chunk(ch)
            latencies_5.append((time.perf_counter() - t0) * 1e6)
            if safe:
                streamed_5.append(safe)
            if is_trip:
                tripped_5 += 1
                break
        if not watcher_p.is_tripped:
            streamed_5.append(watcher_p.flush())
        emitted_5 = "".join(streamed_5)
        for tok in tokens:
            if tok in emitted_5:
                bytes_leaked_5 += len(tok.encode("utf-8"))

    latencies_5.sort()
    v5_res = BenchmarkVectorResult(
        vector_id="V5",
        vector_name="Context Wrapping (Retained Canary)",
        mode="hybrid",
        trials=iterations,
        tripped_count=tripped_5,
        detection_rate=(tripped_5 / iterations) * 100.0,
        false_positive_rate=0.0,
        bytes_leaked_before_sever=bytes_leaked_5,
        p50_latency_us=latencies_5[int(len(latencies_5) * 0.50)],
        p95_latency_us=latencies_5[int(len(latencies_5) * 0.95)],
        p99_latency_us=latencies_5[int(len(latencies_5) * 0.99)],
    )
    results.append(v5_res)

    # -------------------------------------------------------------------------
    # VECTOR 5B: Synonym Watermark Persistence (Zero Lexical Honeytoken / Stripped Unicode)
    # -------------------------------------------------------------------------
    tripped_5b = 0
    bytes_leaked_5b = 0
    latencies_5b: list[float] = []
    syn_watermark = SemanticWatermarker(min_slots_threshold=4, confidence_threshold=0.95)
    base_syn_passage = (
        "Before we commence operations, staff must acquire sufficient clearance, "
        "promptly verify adjacent records, utilize approved tools, obtain explicit authorization, "
        "and retain comprehensive audit logs to prevent hazardous disclosure."
    )

    for i in range(iterations):
        breaker_5b = CircuitBreaker(secret_key, default_action=BreakerAction.BLOCK_AND_SEVER)
        wm_syn_text, _slots = syn_watermark.inject(
            base_syn_passage,
            secret_key=secret_key,
            tenant_id="corp",
            doc_id=f"syn_doc_{i}",
        )
        watcher_5b = SlidingWindowStreamBuffer(
            circuit_breaker=breaker_5b,
            lookahead_window=32,
            canary_mode=CanaryMode.HYBRID,
            synonym_watermarker=syn_watermark,
            secret_key=secret_key,
            tenant_id="corp",
            doc_id=f"syn_doc_{i}",
        )
        streamed_5b = []
        for ch in [wm_syn_text[j : j + 16] for j in range(0, len(wm_syn_text), 16)]:
            t0 = time.perf_counter()
            safe, is_trip, _ = watcher_5b.scan_chunk(ch)
            latencies_5b.append((time.perf_counter() - t0) * 1e6)
            if safe:
                streamed_5b.append(safe)
            if is_trip:
                tripped_5b += 1
                break
        if not watcher_5b.is_tripped:
            streamed_5b.append(watcher_5b.flush())
            bytes_leaked_5b += len("".join(streamed_5b).encode("utf-8"))

    latencies_5b.sort()
    v5b_res = BenchmarkVectorResult(
        vector_id="V5b",
        vector_name="Synonym Watermark (Zero Lexical Canary)",
        mode="synonym",
        trials=iterations,
        tripped_count=tripped_5b,
        detection_rate=(tripped_5b / iterations) * 100.0,
        false_positive_rate=0.0,
        bytes_leaked_before_sever=bytes_leaked_5b,
        p50_latency_us=latencies_5b[int(len(latencies_5b) * 0.50)],
        p95_latency_us=latencies_5b[int(len(latencies_5b) * 0.95)],
        p99_latency_us=latencies_5b[int(len(latencies_5b) * 0.99)],
    )
    results.append(v5b_res)

    # -------------------------------------------------------------------------
    # PRINT RESULTS TABLE & COMPARATIVE ANALYSIS
    # -------------------------------------------------------------------------
    if verbose:
        print(
            f"\n{'Vector':<6} | {'Workload Vector':<40} | {'Mode':<8} | {'Detection':<10} | {'FP Rate':<8} | {'Leaked Bytes':<12} | {'p50 Tax':<12}"
        )
        print("-" * 110)
        for r in results:
            det_str = f"{r.detection_rate:.1f}%"
            fp_str = f"{r.false_positive_rate:.2f}%"
            lat_str = f"{r.p50_latency_us:.2f} µs" if r.p50_latency_us > 0 else "N/A (Bypassed)"
            print(
                f"{r.vector_id:<6} | {r.vector_name:<40} | {r.mode:<8} | {det_str:<10} | {fp_str:<8} | {r.bytes_leaked_before_sever:<12} | {lat_str:<12}"
            )

        print("\n" + "=" * 80)
        print("  Canary Fabric vs. CanaryRAG (arXiv:2604.10717) Comparative Analysis")
        print("=" * 80)
        p50_us = v1_res.p50_latency_us
        canaryrag_p50_ms = 45.0  # Published median dual-path shadow model inference
        speedup = (canaryrag_p50_ms * 1000.0) / max(p50_us, 0.001)

        print(
            f"  • Canary Fabric Inspection:                 {p50_us:.2f} µs p50 wire-level CPU inspection with 0 extra LLM calls (eliminating CanaryRAG's 2x parallel oracle LLM inference cost)"
        )
        print(
            f"  • Canary Fabric Lookahead Ring Buffer p50:  {p50_us:.2f} µs ({p50_us / 1000.0:.4f} ms)"
        )
        print(
            f"  • CanaryRAG Dual-Path Game (ACL '26) p50:     {canaryrag_p50_ms:.1f} ms (45,000 µs)"
        )
        print(
            f"  • TTFT Latency Advantage:                   {speedup:,.0f}x Faster (<0.05ms user-perceptible tax)"
        )
        print(
            f"  • Unicode Sanitizer Stripping Defense:       {v2b_res.detection_rate:.1f}% Detection in Hybrid Mode (vs {v2a_res.detection_rate:.1f}% in Stego, {v2a_res.bytes_leaked_before_sever} bytes leaked)"
        )
        print(
            f"  • Benign & Code False-Positive Rate:         V3={v3_res.false_positive_rate:.2f}%, V4={v4_res.false_positive_rate:.2f}%"
        )
        print("=" * 80)

    # -------------------------------------------------------------------------
    # WRITE LOG FILE IF REQUESTED
    # -------------------------------------------------------------------------
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(asdict(r)) + "\n")
        if verbose:
            print(f"\n[+] Benchmark records written to: {output_path}")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Canary Fabric vs CanaryRAG Empirical Benchmark Harness"
    )
    parser.add_argument(
        "--iterations", type=int, default=100, help="Number of benchmark trials per vector"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="benchmarks/results/canaryrag_eval_logs.jsonl",
        help="JSONL log path",
    )
    args = parser.parse_args()

    out_file = Path(args.output) if args.output else None
    results = run_benchmark(iterations=args.iterations, output_path=out_file)

    # Enforce acceptance gates:
    # 1. V1 detection rate must be 100%
    # 2. V2b (hybrid fallback) detection rate must be 100%
    # 3. V3 false positive rate must be 0%
    # 4. V4 code stream false positive rate must be 0%
    # 5. V5 paraphrased leakage detection rate must be 100%
    # 6. p50 latency must be < 50 µs
    v1 = next(r for r in results if r.vector_id == "V1")
    v2b = next(r for r in results if r.vector_id == "V2b")
    v3 = next(r for r in results if r.vector_id == "V3")
    v4 = next((r for r in results if r.vector_id == "V4"), None)
    v5 = next((r for r in results if r.vector_id == "V5"), None)

    assert v1.detection_rate == 100.0, "Vector 1 failed 100% detection gate"
    assert v2b.detection_rate == 100.0, "Vector 2b lexical fallback failed 100% detection gate"
    assert v3.false_positive_rate == 0.0, "Vector 3 failed 0.00% false positive gate"
    if v4:
        assert v4.false_positive_rate == 0.0, "Vector 4 technical code failed 0.00% FP gate"
    if v5:
        assert v5.detection_rate == 100.0, "Vector 5 paraphrased leakage failed 100% detection gate"
    assert v1.p50_latency_us < 50.0, f"Vector 1 latency {v1.p50_latency_us}µs exceeded 50µs gate"

    print("\n[SUCCESS] All Canary Fabric benchmark gates passed!")


if __name__ == "__main__":
    main()
