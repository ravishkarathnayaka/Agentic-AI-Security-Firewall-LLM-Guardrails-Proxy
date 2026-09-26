"""
Insecure Deserialization and Polyglot Payload Guard for Agent Tool Invocations.

Mitigates OWASP LLM05 (Improper Output Handling), OWASP Top 10 A08 (Software and Data
Integrity Failures), and CWE-502 (Deserialization of Untrusted Data) by detecting
unsafe serialization signatures (Python Pickle, PyYAML tags, Java object streams, PHP injection)
within agent input messages and tool invocation arguments.
"""

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Union


@dataclass
class DeserializationValidationResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed deserialization security checks"
    payload_type_detected: Optional[str] = None
    gadget_signature: Optional[str] = None


class DeserializationGuard:
    """
    Scans data payloads, JSON arguments, and agent strings for dangerous deserialization gadgets.
    """

    # PyYAML dangerous tags
    PYYAML_DANGEROUS_TAGS = re.compile(
        r"!!(?:python/(?:object(?:/apply|/new)?|module|name)|javax?\.[\w\.]+|ruby/object)",
        re.IGNORECASE
    )

    # Python pickle raw opcodes / headers
    # Protocol 0-5 headers: \x80[\x00-\x05] or cos\nsystem or cposix\nsystem
    RAW_PICKLE_OPCODES = re.compile(
        rb"(?:\x80[\x00-\x05]|c(?:os|posix|nt|subprocess)\n(?:system|popen|call|check_output))",
        re.IGNORECASE
    )

    # Base64 encoded pickle: starts with gASV (pickle proto 4/5) or gAJ (proto 2) or K...
    BASE64_PICKLE_PREFIXES = (
        "gASV", "gAJ", "gAN", "gAR"
    )

    # Java serialization magic header: AC ED 00 05 in hex, or rO0AB in base64
    JAVA_MAGIC_BYTES = b"\xac\xed\x00\x05"
    JAVA_B64_PREFIX = "ro0ab"

    # PHP Object Injection: O:8:"ClassName":...
    PHP_OBJECT_INJECTION = re.compile(
        r"(?:^|[\s;{}])O:[0-9]+:\"[a-zA-Z0-9_\\]+\":[0-9]+:\{",
        re.IGNORECASE
    )

    # Insecure JS eval / prototype pollution gadget in serialized JSON
    JS_POLLUTION_GADGETS = re.compile(
        r"(?:__proto__|constructor\s*\[\s*['\"]prototype['\"]\s*\]|__defineGetter__|__lookupGetter__)",
        re.IGNORECASE
    )

    def __init__(self, block_pickles: bool = True, block_yaml_tags: bool = True, block_java: bool = True):
        self.block_pickles = block_pickles
        self.block_yaml_tags = block_yaml_tags
        self.block_java = block_java

    def inspect_text(self, text: str) -> DeserializationValidationResult:
        """
        Scans a text string for dangerous serialized structures.
        """
        if not text or not isinstance(text, str):
            return DeserializationValidationResult(is_blocked=False)

        # 1. PyYAML Dangerous Tags
        if self.block_yaml_tags:
            yaml_match = self.PYYAML_DANGEROUS_TAGS.search(text)
            if yaml_match:
                return DeserializationValidationResult(
                    is_blocked=True,
                    violation_code="unsafe_yaml_deserialization_tag",
                    details=f"Unsafe YAML object/apply execution tag detected: '{yaml_match.group(0)}'",
                    payload_type_detected="yaml_gadget",
                    gadget_signature=yaml_match.group(0)
                )

        # 2. PHP Object Injection
        php_match = self.PHP_OBJECT_INJECTION.search(text)
        if php_match:
            return DeserializationValidationResult(
                is_blocked=True,
                violation_code="php_object_injection",
                details="PHP serialized object injection pattern detected.",
                payload_type_detected="php_serialized",
                gadget_signature=php_match.group(0)
            )

        # 3. JavaScript prototype pollution in raw payload
        js_match = self.JS_POLLUTION_GADGETS.search(text)
        if js_match:
            return DeserializationValidationResult(
                is_blocked=True,
                violation_code="prototype_pollution_gadget",
                details=f"Prototype pollution gadget detected: '{js_match.group(0)}'",
                payload_type_detected="prototype_pollution",
                gadget_signature=js_match.group(0)
            )

        # 4. Check for Base64 encoded Pickles / Java objects
        words = text.split()
        for word in words:
            clean_word = word.strip("'\":,;()[]{}")
            if len(clean_word) >= 16:
                # Java base64 check
                if clean_word.lower().startswith(self.JAVA_B64_PREFIX):
                    return DeserializationValidationResult(
                        is_blocked=True,
                        violation_code="java_serialized_object_detected",
                        details="Base64 encoded Java serialized object stream detected.",
                        payload_type_detected="java_serialized",
                        gadget_signature="rO0AB"
                    )

                # Pickle base64 prefix check
                if any(clean_word.startswith(p) for p in self.BASE64_PICKLE_PREFIXES):
                    try:
                        decoded = base64.b64decode(clean_word, validate=True)
                        if self.RAW_PICKLE_OPCODES.search(decoded):
                            return DeserializationValidationResult(
                                is_blocked=True,
                                violation_code="python_pickle_deserialization_detected",
                                details="Base64 encoded Python pickle byte stream detected with execution opcodes.",
                                payload_type_detected="python_pickle",
                                gadget_signature=clean_word[:12]
                            )
                    except Exception:
                        pass

        # 5. Raw text check for pickle opcode patterns
        raw_bytes = text.encode("utf-8", errors="ignore")
        if self.RAW_PICKLE_OPCODES.search(raw_bytes):
            return DeserializationValidationResult(
                is_blocked=True,
                violation_code="python_pickle_raw_opcodes",
                details="Raw Python pickle command execution opcodes detected.",
                payload_type_detected="python_pickle",
                gadget_signature="raw_pickle"
            )

        return DeserializationValidationResult(is_blocked=False)

    def inspect_tool_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> DeserializationValidationResult:
        """
        Deep scans tool argument dictionary values recursively.
        """
        if not arguments:
            return DeserializationValidationResult(is_blocked=False)

        def _traverse(val: Any) -> Optional[DeserializationValidationResult]:
            if isinstance(val, str):
                res = self.inspect_text(val)
                if res.is_blocked:
                    return res
            elif isinstance(val, dict):
                for k, v in val.items():
                    if isinstance(k, str):
                        res_k = self.inspect_text(k)
                        if res_k.is_blocked:
                            return res_k
                    res_v = _traverse(v)
                    if res_v and res_v.is_blocked:
                        return res_v
            elif isinstance(val, list):
                for item in val:
                    res_i = _traverse(item)
                    if res_i and res_i.is_blocked:
                        return res_i
            return None

        result = _traverse(arguments)
        return result or DeserializationValidationResult(is_blocked=False)
