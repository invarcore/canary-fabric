# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Keyed semantic micro-synonym steganography for tokenizer-resilient canary tripwires."""

import hashlib
import hmac
import math
import re
from typing import NamedTuple

# Curated, high-fidelity formal synonym pairs (Option 0 vs Option 1)
DEFAULT_SYNONYM_PAIRS: list[tuple[str, str]] = [
    ("acquire", "purchase"),
    ("brief", "short"),
    ("vital", "crucial"),
    ("promptly", "quickly"),
    ("utilize", "use"),
    ("commence", "begin"),
    ("terminate", "conclude"),
    ("observe", "notice"),
    ("assist", "help"),
    ("obtain", "secure"),
    ("require", "need"),
    ("sufficient", "adequate"),
    ("verify", "confirm"),
    ("implement", "execute"),
    ("modify", "alter"),
    ("construct", "build"),
    ("indicate", "show"),
    ("select", "choose"),
    ("retain", "keep"),
    ("inform", "notify"),
    ("attempt", "strive"),
    ("permit", "allow"),
    ("provide", "supply"),
    ("reveal", "disclose"),
    ("adjacent", "neighboring"),
    ("initial", "first"),
    ("hazardous", "risky"),
    ("commence", "start"),
    ("comprehensive", "thorough"),
    ("demonstrate", "display"),
    ("establish", "found"),
    ("generate", "create"),
]


class DetectionResult(NamedTuple):
    is_detected: bool
    confidence: float
    total_slots: int
    matching_slots: int
    p_value: float


class SemanticWatermarker:
    """Injects and detects statistical keyed synonym watermarks in plain text.

    Resilient against aggressive tokenizers, OCR, text normalizers, and Unicode filters
    that strip zero-width characters.
    """

    def __init__(
        self,
        synonym_pairs: list[tuple[str, str]] | None = None,
        min_slots_threshold: int = 4,
        confidence_threshold: float = 0.95,
    ) -> None:
        self.pairs = synonym_pairs or DEFAULT_SYNONYM_PAIRS
        self.min_slots = min_slots_threshold
        self.confidence_threshold = confidence_threshold

        # Build fast lookup dictionary: word -> (pair_idx, bit_value, replacement_word)
        self._lookup: dict[str, tuple[int, int, str]] = {}
        for idx, (w0, w1) in enumerate(self.pairs):
            self._lookup[w0.lower()] = (idx, 0, w1)
            self._lookup[w1.lower()] = (idx, 1, w0)

    def _derive_bitstream(self, seed: bytes, length: int) -> list[int]:
        """Derive a deterministic pseudo-random bitstream from a seed using HMAC-SHA256."""
        bits: list[int] = []
        counter = 0
        while len(bits) < length:
            h = hmac.new(seed, f":counter:{counter}".encode(), hashlib.sha256).digest()
            for byte in h:
                for b in range(8):
                    bits.append((byte >> b) & 1)
                    if len(bits) >= length:
                        break
                if len(bits) >= length:
                    break
            counter += 1
        return bits

    def inject(
        self,
        text: str,
        secret_key: str,
        tenant_id: str,
        doc_id: str,
        session_nonce: str | None = None,
    ) -> tuple[str, int]:
        """Inject keyed synonym choices into the text.

        Returns:
            (watermarked_text, slots_modified_count)
        """
        seed = hmac.new(
            secret_key.encode(),
            f"{tenant_id}:{doc_id}:{session_nonce or 'default'}".encode(),
            hashlib.sha256,
        ).digest()

        # Tokenize by words while preserving formatting
        tokens = re.split(r"(\W+)", text)
        slots_found: list[int] = []

        # First pass: find candidate positions
        for i, token in enumerate(tokens):
            clean_word = token.strip().lower()
            if clean_word in self._lookup:
                slots_found.append(i)

        if not slots_found:
            return text, 0

        # Derive target bits for each slot
        target_bits = self._derive_bitstream(seed, len(slots_found))
        modified = 0

        for slot_idx, token_pos in enumerate(slots_found):
            current_token = tokens[token_pos]
            clean_word = current_token.strip().lower()
            pair_idx, current_bit, other_word = self._lookup[clean_word]
            desired_bit = target_bits[slot_idx]

            if current_bit != desired_bit:
                # Apply word substitution matching case
                if current_token.isupper():
                    replacement = other_word.upper()
                elif current_token and current_token[0].isupper():
                    replacement = other_word.capitalize()
                else:
                    replacement = other_word

                tokens[token_pos] = replacement
                modified += 1

        return "".join(tokens), modified

    def detect(
        self,
        text: str,
        secret_key: str,
        tenant_id: str,
        doc_id: str,
        session_nonce: str | None = None,
    ) -> DetectionResult:
        """Statistically verify whether the observed synonym choices match the keyed pseudo-random stream."""
        seed = hmac.new(
            secret_key.encode(),
            f"{tenant_id}:{doc_id}:{session_nonce or 'default'}".encode(),
            hashlib.sha256,
        ).digest()

        tokens = re.split(r"\W+", text)
        observed_bits: list[int] = []

        for token in tokens:
            clean_word = token.strip().lower()
            if clean_word in self._lookup:
                _, bit, _ = self._lookup[clean_word]
                observed_bits.append(bit)

        total_slots = len(observed_bits)
        if total_slots < self.min_slots:
            return DetectionResult(
                is_detected=False,
                confidence=0.0,
                total_slots=total_slots,
                matching_slots=0,
                p_value=1.0,
            )

        expected_bits = self._derive_bitstream(seed, total_slots)
        matching = sum(1 for obs, exp in zip(observed_bits, expected_bits) if obs == exp)

        # Calculate exact binomial cumulative probability under H0 (p=0.5)
        # p_val = sum_{i=matching}^{total} nCr(total, i) * 0.5^total
        p_val = 0.0
        for i in range(matching, total_slots + 1):
            comb = math.comb(total_slots, i)
            p_val += comb * (0.5**total_slots)

        confidence = 1.0 - p_val
        is_detected = (
            total_slots >= self.min_slots
            and matching / total_slots >= 0.75
            and confidence >= self.confidence_threshold
        )

        return DetectionResult(
            is_detected=is_detected,
            confidence=round(confidence, 4),
            total_slots=total_slots,
            matching_slots=matching,
            p_value=round(p_val, 6),
        )