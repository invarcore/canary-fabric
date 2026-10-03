"""Integration tests for watermarking real-world financial prose (SEC EDGAR Form 10-K).

Validates zero-width steganography, Unicode typography resilience, forensic extraction,
and exfiltration detection against realistic corporate financial disclosures.
"""

from __future__ import annotations

import base64
from pathlib import Path

from canary_fabric.core.crypto import sign_payload, verify_signature
from canary_fabric.core.honeytoken import HoneytokenGenerator, HoneytokenType
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder
from canary_fabric.forensics import IncidentVault, LeakCertificate

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "corpora"


def test_sec_edgar_fixture_integrity() -> None:
    """Ensure the SEC EDGAR Form 10-K fixture exists and contains expected sections."""
    sec_file = FIXTURES_DIR / "sec_edgar_10k_excerpt.txt"
    assert sec_file.exists(), f"Missing SEC fixture: {sec_file}"

    content = sec_file.read_text(encoding="utf-8")
    assert "UNITED STATES SECURITIES AND EXCHANGE COMMISSION" in content
    assert "ITEM 1A. RISK FACTORS" in content
    assert "Cloud Infrastructure Revenue" in content
    assert "ASC Topic 606" in content
    assert len(content.split()) >= 400


def test_zero_width_watermark_injection_and_extraction() -> None:
    """Test injecting and recovering a canary token in multi-paragraph financial prose."""
    sec_file = FIXTURES_DIR / "sec_edgar_10k_excerpt.txt"
    original_text = sec_file.read_text(encoding="utf-8")

    canary_token = "7F8A9E1D4B2C0F1A"
    watermarked_text = WatermarkEncoder.inject_watermark(
        original_text, canary_token, strategy="organic"
    )

    # Invisible: visible text length and word count should match visually
    assert len(watermarked_text) > len(original_text)
    # The clean visible characters should match
    cleaned_visible = "".join(
        c for c in watermarked_text if c not in ("\u200e", "\u200f", "\u200b", "\u200c", "\u200d", "\ufeff")
    )
    assert cleaned_visible == original_text

    # Extract tokens and verify 100% recovery
    extracted = WatermarkDecoder.extract_tokens(watermarked_text)
    assert canary_token in extracted


def test_unicode_smart_quotes_and_table_resilience() -> None:
    """Verify steganography payload survives adjacent to unicode quotes, dashes, and tables."""
    sec_file = FIXTURES_DIR / "sec_edgar_10k_excerpt.txt"
    text = sec_file.read_text(encoding="utf-8")

    # Extract the section with em-dashes and risk factor disclosures
    start_idx = text.find("PART I — ITEM 1A. RISK FACTORS")
    assert start_idx != -1
    target_section = text[start_idx : start_idx + 350]

    secret_key = "0123456789abcdef0123456789abcdef"
    payload = {"doc": "SEC-EDGAR-DOC-2025"}
    signature = sign_payload(secret_key, payload)
    token = signature[:16].upper()

    watermarked = WatermarkEncoder.inject_watermark(target_section, token, strategy="organic")
    tokens = WatermarkDecoder.extract_tokens(watermarked)

    assert token in tokens
    # Verify cryptographic signature verification
    assert verify_signature(secret_key, payload, signature)


def test_forensic_exfiltration_detection_and_provenance() -> None:
    """Test forensic leak detection on an exfiltrated snippet of financial disclosures."""
    sec_file = FIXTURES_DIR / "sec_edgar_10k_excerpt.txt"
    text = sec_file.read_text(encoding="utf-8")

    token = "E3B0C44298FC1C14"
    watermarked_corpus = WatermarkEncoder.inject_watermark(text, token, strategy="organic")

    # Threat actor extracts only the first 2 paragraphs (which contain the watermark)
    exfiltrated_slice = "\n\n".join(watermarked_corpus.split("\n\n")[:3])
    assert len(exfiltrated_slice) < len(watermarked_corpus)

    # Detect extracted tokens
    extracted_tokens = WatermarkDecoder.extract_tokens(exfiltrated_slice)
    assert token in extracted_tokens

    # Generate cryptographic LeakCertificate and store in IncidentVault
    vault = IncidentVault(":memory:")
    cert = LeakCertificate(
        certificate_id="cert_sec_leak_001",
        tenant_id="enterprise-corp",
        source_doc_id="sec-10k-fy2025",
        source_chunk_id="chunk_0",
        canary_token=token,
    ).sign("secops-audit-key")

    assert cert.verify("secops-audit-key") is True
    vault.record_certificate(cert)

    stored = vault.list_incidents(tenant_id="enterprise-corp")
    assert len(stored) == 1
    assert stored[0].canary_token == token


def test_base64_encoded_exfiltration_evasion() -> None:
    """Test detection when threat actor attempts base64 encoding the exfiltrated text."""
    sec_file = FIXTURES_DIR / "sec_edgar_10k_excerpt.txt"
    text = sec_file.read_text(encoding="utf-8")

    generator = HoneytokenGenerator()
    honeytoken = generator.generate(
        token_type=HoneytokenType.JWT_SECRET,
        tenant_id="enterprise-corp",
        doc_id="sec-10k-2025",
    )
    assert honeytoken.value.startswith("canary_jwt_secret_")

    # Inject token into financial report
    watermarked = WatermarkEncoder.inject_watermark(text, "A1B2C3D4E5F67890", strategy="organic")

    # Encode excerpt into base64 string (common exfiltration technique)
    b64_payload = base64.b64encode(watermarked[:300].encode("utf-8")).decode("ascii")
    carrier = f"Here is the encoded diagnostics dump: {b64_payload} for debugging."

    extracted = WatermarkDecoder.extract_tokens(carrier)
    assert "A1B2C3D4E5F67890" in extracted
