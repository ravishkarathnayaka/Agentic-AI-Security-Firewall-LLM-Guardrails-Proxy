"""
Context Bomb and Recursive Resource Exhaustion Guard.

Mitigates OWASP LLM04 (Model Denial of Service), CWE-400 (Uncontrolled Resource Consumption),
and CWE-776 (XML/YAML Entity Expansion / Billion Laughs) by inspecting payloads for
recursive references, deep container nesting, decompression bombs, and exponential token expansions.
"""

import base64
import json
import re
import zlib
from dataclasses import dataclass
from typing import Optional, Any, Dict, List, Union


@dataclass
class ContextBombResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed context bomb and resource exhaustion check"
    bomb_type: Optional[str] = None
    measured_metric: Optional[float] = None


class ContextBombGuard:
    """
    Guards against algorithmic complexity and context bomb attacks.
    """

    # XML Billion Laughs and DTD entity definitions
    XML_ENTITY_EXPANSION = re.compile(
        r"<!ENTITY\s+([a-zA-Z0-9_\-]+)\s+[\"'](&[a-zA-Z0-9_\-]+;)+[\"']",
        re.IGNORECASE
    )

    # General DTD declarations in text
    XML_DOCTYPE_DTD = re.compile(
        r"<!DOCTYPE\s+[a-zA-Z0-9_\-]+\s*\[",
        re.IGNORECASE
    )

    # YAML anchor multiplication: &a [*a, *a, *a]
    YAML_ANCHOR_EXPANSION = re.compile(
        r"&\w+\s*\[(?:\s*\*\w+\s*,?){3,}\]",
        re.IGNORECASE
    )

    # Suspicious prompt repetition instructions designed to trick LLMs into infinite generation
    RECURSIVE_EXPANSION_DIRECTIVE = re.compile(
        r"(?:repeat\s+(?:the\s+following\s+)?(?:phrase|word|text|token|symbol|string)?\s*(?:\d{4,}|infinitely|forever|ad\s+infinitum|unlimited|without\s+stopping)|expand\s+(?:exponentially|ad\s+infinitum))",
        re.IGNORECASE
    )

    def __init__(
        self,
        max_json_depth: int = 30,
        max_decompression_ratio: float = 50.0,
        max_decompressed_bytes: int = 500_000,
        max_text_repetition_ratio: float = 0.85
    ):
        self.max_json_depth = max_json_depth
        self.max_decompression_ratio = max_decompression_ratio
        self.max_decompressed_bytes = max_decompressed_bytes
        self.max_text_repetition_ratio = max_text_repetition_ratio

    def inspect_text(self, text: str) -> ContextBombResult:
        """
        Inspects text for XML/YAML entity bombs, decompression bombs, or recursive directives.
        """
        if not text or not isinstance(text, str):
            return ContextBombResult(is_blocked=False)

        # 1. XML Billion Laughs DTD Entity Expansion
        if self.XML_DOCTYPE_DTD.search(text) and self.XML_ENTITY_EXPANSION.search(text):
            return ContextBombResult(
                is_blocked=True,
                violation_code="xml_entity_expansion_bomb",
                details="XML recursive entity expansion (Billion Laughs) bomb detected.",
                bomb_type="billion_laughs"
            )

        # 2. YAML Anchor Multiplication Bomb
        if self.YAML_ANCHOR_EXPANSION.search(text):
            return ContextBombResult(
                is_blocked=True,
                violation_code="yaml_anchor_expansion_bomb",
                details="YAML recursive anchor multiplication bomb detected.",
                bomb_type="yaml_bomb"
            )

        # 3. Recursive Generation Exhaustion Directive
        if self.RECURSIVE_EXPANSION_DIRECTIVE.search(text):
            return ContextBombResult(
                is_blocked=True,
                violation_code="recursive_generation_exhaustion_attempt",
                details="Prompt directive attempting to force exponential/infinite token generation DoS.",
                bomb_type="recursive_directive"
            )

        # 4. Check potential embedded base64 decompression bombs
        words = text.split()
        for word in words:
            clean = word.strip("'\":,;()[]{}")
            if len(clean) > 40 and clean.startswith(("H4sI", "eJ", "eN")):
                res_b64 = self.inspect_base64_decompression(clean)
                if res_b64.is_blocked:
                    return res_b64

        return ContextBombResult(is_blocked=False)

    def inspect_json_depth(self, data: Any, current_depth: int = 1) -> ContextBombResult:
        """
        Recursively measures nesting depth of JSON objects or arrays to prevent stack exhaustion.
        """
        if current_depth > self.max_json_depth:
            return ContextBombResult(
                is_blocked=True,
                violation_code="excessive_container_nesting_depth",
                details=f"Container nesting depth ({current_depth}) exceeds maximum limit ({self.max_json_depth}).",
                bomb_type="json_nesting_bomb",
                measured_metric=float(current_depth)
            )

        if isinstance(data, dict):
            for v in data.values():
                res = self.inspect_json_depth(v, current_depth + 1)
                if res.is_blocked:
                    return res
        elif isinstance(data, list):
            for item in data:
                res = self.inspect_json_depth(item, current_depth + 1)
                if res.is_blocked:
                    return res

        return ContextBombResult(is_blocked=False)

    def inspect_base64_decompression(self, b64_str: str) -> ContextBombResult:
        """
        Inspects base64 encoded compressed data for decompression bombs (high compression ratio).
        """
        try:
            compressed = base64.b64decode(b64_str, validate=True)
        except Exception:
            return ContextBombResult(is_blocked=False)

        compressed_len = len(compressed)
        if compressed_len < 16:
            return ContextBombResult(is_blocked=False)

        # Decompress safely with bounded buffer
        try:
            # Try zlib
            decompressor = zlib.decompressobj()
            decompressed = decompressor.decompress(compressed, max_length=self.max_decompressed_bytes + 1)
            decompressed_len = len(decompressed)

            if decompressed_len > self.max_decompressed_bytes:
                return ContextBombResult(
                    is_blocked=True,
                    violation_code="decompression_size_limit_exceeded",
                    details=f"Decompressed payload size exceeds safe limit ({self.max_decompressed_bytes} bytes).",
                    bomb_type="zip_bomb",
                    measured_metric=float(decompressed_len)
                )

            ratio = decompressed_len / max(1, compressed_len)
            if ratio > self.max_decompression_ratio and decompressed_len > 10_000:
                return ContextBombResult(
                    is_blocked=True,
                    violation_code="high_expansion_decompression_bomb",
                    details=f"Extreme compression expansion ratio detected ({ratio:.1f}:1).",
                    bomb_type="zip_bomb",
                    measured_metric=ratio
                )
        except Exception:
            pass

        return ContextBombResult(is_blocked=False)
