"""Recursive Multi-Tier Unpacking & Normalization Guard.

Defeats multi-layered encoding evasions (nested URL encoding, HTML entity obfuscation,
Base64 wrapping, and Unicode/hex escape sequencing) by recursively unpacking payloads
for downstream inspection.
"""

import base64
import html
import re
import urllib.parse
from typing import List, Set


class NestedUnpackGuard:
    """Iteratively unpacks and canonicalizes nested encodings to expose hidden payloads."""

    BASE64_CANDIDATE_REGEX = re.compile(r"\b[A-Za-z0-9+/]{12,}={0,2}\b")
    HEX_ESCAPE_REGEX = re.compile(r"\\x([0-9a-fA-F]{2})")
    UNICODE_ESCAPE_REGEX = re.compile(r"\\u([0-9a-fA-F]{4})")

    def __init__(self, max_depth: int = 4):
        self.max_depth = max_depth

    def _decode_hex_and_unicode(self, text: str) -> str:
        """Decode literal \\xHH and \\uHHHH sequences if present."""
        def replace_hex(match):
            try:
                return chr(int(match.group(1), 16))
            except Exception:
                return match.group(0)

        def replace_unicode(match):
            try:
                return chr(int(match.group(1), 16))
            except Exception:
                return match.group(0)

        if "\\x" in text:
            text = self.HEX_ESCAPE_REGEX.sub(replace_hex, text)
        if "\\u" in text:
            text = self.UNICODE_ESCAPE_REGEX.sub(replace_unicode, text)
        return text

    def _decode_base64_candidates(self, text: str) -> str:
        """Find base64 candidate strings and replace with decoded utf-8 text if valid."""
        def replace_b64(match):
            candidate = match.group(0)
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                # Ensure it produced printable text
                if all(c.isprintable() or c in "\r\n\t" for c in decoded_str):
                    return decoded_str
            except Exception:
                pass
            return candidate

        return self.BASE64_CANDIDATE_REGEX.sub(replace_b64, text)

    def unpack_all_variants(self, original_text: str) -> List[str]:
        """Generate all unpacked and intermediate representations of the text.
        
        Returns:
            A list of unique strings starting with the most deeply decoded variant.
        """
        if not original_text:
            return [original_text]

        seen: Set[str] = set()
        current = original_text
        variants: List[str] = []

        for _ in range(self.max_depth):
            if current in seen:
                break
            seen.add(current)
            variants.append(current)

            # 1. URL decoding
            url_decoded = urllib.parse.unquote(current)

            # 2. HTML entity unescaping
            html_decoded = html.unescape(url_decoded)

            # 3. Hex and Unicode escapes
            escaped_decoded = self._decode_hex_and_unicode(html_decoded)

            # 4. Embedded Base64
            b64_decoded = self._decode_base64_candidates(escaped_decoded)

            if b64_decoded == current:
                break
            current = b64_decoded

        if current not in seen:
            seen.add(current)
            variants.append(current)

        # Return in order of deepest unpacked first
        return list(reversed(variants))
