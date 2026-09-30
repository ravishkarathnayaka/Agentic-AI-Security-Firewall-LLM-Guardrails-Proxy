"""
Structured Output Schema Validator Guard
========================================
Validates LLM and agent JSON responses against developer-specified schemas.
Prevents type confusion, missing critical security fields, schema drift,
and trailing injection payloads appended after JSON structures.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Type


@dataclass
class SchemaValidationResult:
    is_valid: bool
    parsed_data: Optional[Dict[str, Any]] = None
    violation_code: Optional[str] = None
    details: Optional[str] = None


class StructuredOutputSchemaValidatorGuard:
    """
    Validates outbound JSON payloads against expected schema constraints.
    """

    TYPE_MAP = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    def validate_json_response(
        self,
        raw_text: str,
        expected_schema: Dict[str, Any]
    ) -> SchemaValidationResult:
        """
        Validates raw model output against a JSON schema specification.
        expected_schema format:
        {
            "type": "object",
            "required": ["field1", "field2"],
            "properties": {
                "field1": {"type": "string"},
                "field2": {"type": "integer"}
            }
        }
        """
        if not raw_text or not raw_text.strip():
            return SchemaValidationResult(
                is_valid=False,
                violation_code="empty_model_response",
                details="Model output was empty or whitespace only",
            )

        # Parse JSON
        try:
            data = json.loads(raw_text.strip())
        except Exception as e:
            return SchemaValidationResult(
                is_valid=False,
                violation_code="invalid_json_syntax",
                details=f"Model output is not valid JSON: {str(e)}",
            )

        if not isinstance(data, dict):
            return SchemaValidationResult(
                is_valid=False,
                violation_code="non_object_json_root",
                details="Expected top-level JSON object/dictionary",
            )

        # Check required fields
        required_fields = expected_schema.get("required", [])
        for req in required_fields:
            if req not in data:
                return SchemaValidationResult(
                    is_valid=False,
                    violation_code="missing_required_field",
                    details=f"Required field '{req}' missing from structured output",
                )

        # Check property types
        props = expected_schema.get("properties", {})
        for key, prop_def in props.items():
            if key in data:
                exp_type_name = prop_def.get("type")
                if exp_type_name in self.TYPE_MAP:
                    exp_type = self.TYPE_MAP[exp_type_name]
                    # In python, bool is a subclass of int, so handle bool explicitly
                    val = data[key]
                    if exp_type_name in ("integer", "number") and isinstance(val, bool):
                        return SchemaValidationResult(
                            is_valid=False,
                            violation_code="schema_type_mismatch",
                            details=f"Field '{key}' expected {exp_type_name}, but received boolean",
                        )
                    if not isinstance(val, exp_type):
                        return SchemaValidationResult(
                            is_valid=False,
                            violation_code="schema_type_mismatch",
                            details=(
                                f"Field '{key}' expected type {exp_type_name}, but "
                                f"received {type(val).__name__}"
                            ),
                        )

        return SchemaValidationResult(is_valid=True, parsed_data=data)
