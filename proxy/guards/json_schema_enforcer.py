"""Structured Output & Outbound JSON Schema Enforcer.

Enforces schema contracts, prevents downstream prototype/script injection in agent
structured outputs, and neutralizes nested JSON bomb DoS vectors.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union


class StructuredOutputEnforcer:
    """Validates structured JSON output from LLM agents against strict schema constraints."""

    # Unsafe script/injection patterns inside JSON strings
    UNSAFE_PAYLOAD_PATTERNS = [
        re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
        re.compile(r"__proto__|constructor|prototype", re.IGNORECASE),
        re.compile(r"<\s*iframe|onload\s*=|onerror\s*=", re.IGNORECASE),
    ]

    def __init__(self, max_depth: int = 8, max_keys: int = 100):
        self.max_depth = max_depth
        self.max_keys = max_keys

    def _check_depth_and_keys(self, obj: Any, current_depth: int = 0) -> Tuple[bool, Optional[str]]:
        if current_depth > self.max_depth:
            return False, f"JSON nesting exceeds maximum depth limit of {self.max_depth}"

        if isinstance(obj, dict):
            if len(obj) > self.max_keys:
                return False, f"JSON dictionary exceeds maximum key limit of {self.max_keys}"
            for k, v in obj.items():
                if not isinstance(k, str):
                    return False, "JSON object keys must be strings"
                # Check key for dangerous prototype pollution
                if k in ("__proto__", "constructor", "prototype"):
                    return False, f"Prototype pollution key detected: {k}"
                ok, err = self._check_depth_and_keys(v, current_depth + 1)
                if not ok:
                    return False, err
        elif isinstance(obj, list):
            if len(obj) > self.max_keys:
                return False, f"JSON array exceeds maximum element limit of {self.max_keys}"
            for item in obj:
                ok, err = self._check_depth_and_keys(item, current_depth + 1)
                if not ok:
                    return False, err
        elif isinstance(obj, str):
            for pat in self.UNSAFE_PAYLOAD_PATTERNS:
                if pat.search(obj):
                    return False, f"Unsafe script or payload pattern detected in structured output: '{obj[:40]}...'"

        return True, None

    def validate_json_string(
        self,
        raw_json: str,
        required_keys: Optional[List[str]] = None,
        expected_schema: Optional[Dict[str, type]] = None,
    ) -> Tuple[bool, Optional[str], Optional[Union[Dict, List]]]:
        """Validate and parse structured JSON string.
        
        Returns:
            (is_valid, error_message, parsed_object)
        """
        if not raw_json or not raw_json.strip():
            return False, "Empty JSON payload", None

        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            return False, f"JSON syntax error: {str(exc)}", None

        # 1. Depth & key safety check
        is_safe, safety_err = self._check_depth_and_keys(parsed)
        if not is_safe:
            return False, safety_err, None

        # 2. Key requirements
        if isinstance(parsed, dict) and required_keys:
            for req in required_keys:
                if req not in parsed:
                    return False, f"Missing required property: '{req}'", None

        # 3. Expected schema types
        if isinstance(parsed, dict) and expected_schema:
            for key, expected_type in expected_schema.items():
                if key in parsed:
                    val = parsed[key]
                    if not isinstance(val, expected_type):
                        return (
                            False,
                            f"Property '{key}' must be of type {expected_type.__name__}, got {type(val).__name__}",
                            None,
                        )

        return True, None, parsed
