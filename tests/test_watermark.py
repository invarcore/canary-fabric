"""Tests for 4-ary Zero-Width Unicode Steganography."""

from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder


def test_zerowidth_encode_decode_roundtrip():
    hex_token = "7F8A9E1D2C3B4A5E"
    encoded = WatermarkEncoder.encode_hex_to_zerowidth(hex_token)
    assert len(encoded) > 0

    # Verify all characters in encoded are zero-width / formatting
    for ch in encoded:
        assert ch in ["\u200b", "\u200c", "\u200d", "\ufeff", "\u200e", "\u200f"]

    extracted = WatermarkDecoder.extract_tokens(encoded)
    assert len(extracted) == 1
    assert extracted[0] == hex_token


def test_inject_into_text_and_extract():
    text = "Confidential financial results for Q3 2026. Net profit rose 35%."
    token = "DEADBEEFCAFE1234"
    watermarked = WatermarkEncoder.inject_watermark(text, token, strategy="organic")

    # Stripped text should match original printable content
    stripped = WatermarkDecoder.strip_watermarks(watermarked)
    assert stripped == text

    # Extract tokens from watermarked text
    tokens = WatermarkDecoder.extract_tokens(watermarked)
    assert token in tokens
    assert WatermarkDecoder.contains_watermark(watermarked, token) is True
    assert WatermarkDecoder.contains_watermark(watermarked, "NONEXISTENT") is False


def test_clean_text_has_no_watermarks():
    clean_text = "This is a clean document with no hidden zero width characters."
    assert WatermarkDecoder.extract_tokens(clean_text) == []
    assert WatermarkDecoder.contains_watermark(clean_text) is False
