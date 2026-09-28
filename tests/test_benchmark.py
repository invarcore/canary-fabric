"""Performance benchmark testing latency overhead of the sliding-window scanner."""

import time

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
