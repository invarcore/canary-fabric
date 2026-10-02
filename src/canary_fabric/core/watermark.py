"""4-ary Zero-Width Unicode Steganography Encoder, Decoder, and Injector."""

import re

# 4-ary Zero-Width Alphabet mapping (2 bits per character)
# Data characters: \u200B, \u200C, \u200D, \uFEFF
ZW_MAP = {
    "00": "\u200b",
    "01": "\u200c",
    "10": "\u200d",
    "11": "\ufeff",
}

REV_ZW_MAP = {v: k for k, v in ZW_MAP.items()}

# Boundary Framing Sentinels (using distinct LRM \u200E and RLM \u200F to avoid collision with data alphabet)
ZW_START = "\u200e\u200f"
ZW_END = "\u200f\u200e"

# Regex pattern matching framed zero-width tokens
ZW_PATTERN = re.compile(f"{ZW_START}([\u200b\u200c\u200d\ufeff]+?){ZW_END}")


class WatermarkEncoder:
    """Encodes canary tokens into invisible zero-width Unicode sequences."""

    @staticmethod
    def encode_hex_to_zerowidth(hex_str: str) -> str:
        """Encode a hex string (e.g. '7F8A9E1D') into a framed zero-width Unicode string."""
        clean_hex = hex_str.strip().upper()
        # Convert hex to binary string
        binary_str = bin(int(clean_hex, 16))[2:].zfill(len(clean_hex) * 4)

        # Group into 2-bit chunks
        zw_chars = []
        for i in range(0, len(binary_str), 2):
            bit_pair = binary_str[i : i + 2]
            zw_chars.append(ZW_MAP[bit_pair])

        encoded_payload = "".join(zw_chars)
        return f"{ZW_START}{encoded_payload}{ZW_END}"

    @classmethod
    def inject_watermark(
        cls,
        text: str,
        canary_token: str,
        frequency: int = 1,
        strategy: str = "organic",
    ) -> str:
        """Invisibly inject canary watermark into text at natural word or sentence boundaries."""
        zw_token = cls.encode_hex_to_zerowidth(canary_token)
        if not text:
            return zw_token

        if strategy == "organic":
            # Inject after punctuation marks (., !, ?, ;, :) or space boundaries
            puncts = [". ", "! ", "? ", "; ", ", "]
            for p in puncts:
                if p in text:
                    parts = text.split(p, 1)
                    return f"{parts[0]}{p[:-1]}{zw_token} {parts[1]}"

            # Fallback: inject after the first word boundary
            words = text.split(" ", 1)
            if len(words) > 1:
                return f"{words[0]}{zw_token} {words[1]}"
            return f"{text}{zw_token}"

        elif strategy == "prefix":
            return f"{zw_token}{text}"
        elif strategy == "suffix":
            return f"{text}{zw_token}"
        else:
            return f"{text}{zw_token}"


class WatermarkDecoder:
    """Extracts, verifies, and strips zero-width canary watermarks from text."""

    @classmethod
    def extract_tokens(cls, text: str) -> list[str]:
        """Extract all valid hex canary tokens found in the input text or base64 encoded sections."""
        if not text:
            return []

        tokens: list[str] = cls._extract_from_text(text)

        # Also inspect potential base64 encoded strings for concealed tokens
        import base64
        for b64_match in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
            candidate = b64_match.group()
            try:
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded_bytes = base64.b64decode(padded)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if any(c in decoded_text for c in ("\u200e", "\u200f", "\u200b", "\u200c", "\u200d", "\ufeff")):
                    for sub_token in cls._extract_from_text(decoded_text):
                        if sub_token not in tokens:
                            tokens.append(sub_token)
            except Exception:
                continue

        return tokens

    @staticmethod
    def _extract_from_text(text: str) -> list[str]:
        tokens: list[str] = []
        matches = ZW_PATTERN.findall(text)

        for match in matches:
            bit_chunks = []
            valid = True
            for ch in match:
                bits = REV_ZW_MAP.get(ch)
                if bits is not None:
                    bit_chunks.append(bits)
                else:
                    valid = False
                    break

            if not valid or not bit_chunks:
                continue

            binary_str = "".join(bit_chunks)
            if len(binary_str) % 4 != 0:
                continue

            try:
                hex_val = hex(int(binary_str, 2))[2:].upper()
                expected_hex_len = len(binary_str) // 4
                hex_token = hex_val.zfill(expected_hex_len)
                tokens.append(hex_token)
            except ValueError:
                continue

        return tokens

    @classmethod
    def contains_watermark(cls, text: str, target_token: str | None = None) -> bool:
        """Check if the text contains any watermark, or a specific target token."""
        extracted = cls.extract_tokens(text)
        if not extracted:
            return False
        if target_token is None:
            return len(extracted) > 0
        return target_token.upper() in extracted

    @staticmethod
    def strip_watermarks(text: str) -> str:
        """Strip all zero-width and directional formatting characters from text."""
        if not text:
            return ""
        return re.sub(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F]", "", text)
