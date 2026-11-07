# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmark testing latency overhead of the sliding-window scanner."""

import time
from pathlib import Path

from benchmarks.run_canaryrag_eval import run_benchmark
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder


def test_sub_millisecond_scan_latency():
    """Assert average token scan latency is strictly below 0.8ms (800 microseconds)."""
    text = (
        "Enterprise intelligence briefing: Acme Corporation will acquire CyberShield on Oct 10th "
        "for $1.2B in cash and stock. Project code name is ODYSSEY."
    )
    token = "8F9E0A1B2C3D4E5F"
    watermarked = WatermarkEncoder.inject_watermark(text, token)

    iterations = 2000
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = WatermarkDecoder.extract_tokens(watermarked)
    elapsed_total = time.perf_counter() - t0

    avg_ms = (elapsed_total / iterations) * 1000.0
    # Average scan should be well below 0.8ms (typically <0.05ms)
    assert avg_ms < 0.8, f"Scan latency {avg_ms:.4f}ms exceeded 0.8ms threshold"


def test_canaryrag_comparative_benchmark_harness(tmp_path: Path):
    """Verify reproducible CanaryRAG benchmark runs cleanly and satisfies all gates."""
    log_file = tmp_path / "canaryrag_eval.jsonl"
    results = run_benchmark(iterations=10, output_path=log_file, verbose=False)

    assert len(results) == 4
    v1 = next(r for r in results if r.vector_id == "V1")
    v2a = next(r for r in results if r.vector_id == "V2a")
    v2b = next(r for r in results if r.vector_id == "V2b")
    v3 = next(r for r in results if r.vector_id == "V3")

    assert v1.detection_rate == 100.0
    assert v2a.detection_rate == 0.0  # Demonstrates bypass under Unicode stripping
    assert v2b.detection_rate == 100.0  # Demonstrates lexical fallback mitigation
    assert v3.false_positive_rate == 0.0
    assert log_file.exists()
