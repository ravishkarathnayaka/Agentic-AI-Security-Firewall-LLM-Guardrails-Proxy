"""Tool Argument JSON Schema Mutation & Prototype Hijack Guard.

Prevents prototype pollution, unexpected schema additions, parameter smuggling,
and object property hijacking in dynamic agentic tool invocations.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class SchemaMutationGuard:
    """Detects prototype pollution, parameter mutation, and prototype hijacking in tool arguments."""

    POLLUTION_KEYS: Set[str] = {
        "__proto__",
        "constructor",
        "prototype",
        "__class__",
        "__bases__",
        "__subclasses__",
        "__globals__",
        "__builtins__",
        "__code__",
    }

    def __init__(
        self,
        enabled: bool = True,
        strict_schema_enforcement: bool = True,
        max_traversal_depth: int = 10,
    ) -> None:
        self.enabled = enabled
        self.strict_schema_enforcement = strict_schema_enforcement
        self.max_traversal_depth = max_traversal_depth

    def _check_pollution(self, obj: Any, depth: int = 0) -> Tuple[bool, Optional[str]]:
        """Recursively scan dictionaries and lists for prototype pollution keys."""
        if depth > self.max_traversal_depth:
            return False, f"Maximum argument nesting depth of {self.max_traversal_depth} exceeded"

        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in self.POLLUTION_KEYS or k in self.POLLUTION_KEYS:
                    return False, f"Prototype pollution key detected in tool arguments: '{k}'"
                
                # Check for string representation of proto injection
                if isinstance(v, str):
                    if any(p in v for p in ('"__proto__"', '"constructor"', '"prototype"')):
                        # Attempt to parse nested JSON if it looks like a JSON object
                        stripped = v.strip()
                        if stripped.startswith("{") and stripped.endswith("}"):
                            try:
                                parsed = json.loads(stripped)
                                ok, reason = self._check_pollution(parsed, depth + 1)
                                if not ok:
                                    return False, reason
                            except Exception:
                                pass

                ok, reason = self._check_pollution(v, depth + 1)
                if not ok:
                    return False, reason

        elif isinstance(obj, list):
            for item in obj:
                ok, reason = self._check_pollution(item, depth + 1)
                if not ok:
                    return False, reason

        return True, None

    def validate_tool_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        expected_schema: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Validate tool invocation arguments against prototype pollution and schema mutation.
        
        Args:
            tool_name: Name of the invoked tool.
            arguments: Dictionary of arguments supplied to the tool.
            expected_schema: Optional expected schema dictionary defining valid properties and types.
            
        Returns:
            Tuple of (is_valid, error_reason)
        """
        if not self.enabled:
            return True, None

        if not isinstance(arguments, dict):
            return False, f"Tool arguments for '{tool_name}' must be a dictionary, got {type(arguments).__name__}"

        # 1. Scan for prototype pollution keys at any depth
        is_safe, error = self._check_pollution(arguments)
        if not is_safe:
            return False, f"Schema mutation blocked for '{tool_name}': {error}"

        # 2. If expected schema is provided, enforce strictly against mutations
        if expected_schema and self.strict_schema_enforcement:
            properties = expected_schema.get("properties", {})
            required = expected_schema.get("required", [])

            # Check missing required fields
            for req in required:
                if req not in arguments:
                    return False, f"Schema violation for '{tool_name}': Missing required argument '{req}'"

            # Check undeclared / smuggled parameters
            for key, val in arguments.items():
                if key not in properties:
                    return False, f"Schema mutation violation for '{tool_name}': Undeclared argument '{key}' is not permitted"

                # Check expected type
                param_spec = properties[key]
                expected_type = param_spec.get("type")
                if expected_type:
                    type_ok = self._validate_primitive_type(val, expected_type)
                    if not type_ok:
                        return (
                            False,
                            f"Type confusion mutation for '{tool_name}.{key}': Expected type '{expected_type}', got '{type(val).__name__}'",
                        )

        return True, None

    @staticmethod
    def _validate_primitive_type(val: Any, expected_type: str) -> bool:
        """Validate value matches the declared JSON schema type."""
        if expected_type == "string":
            return isinstance(val, str)
        if expected_type == "number":
            return isinstance(val, (int, float)) and not isinstance(val, bool)
        if expected_type == "integer":
            return isinstance(val, int) and not isinstance(val, bool)
        if expected_type == "boolean":
            return isinstance(val, bool)
        if expected_type == "array":
            return isinstance(val, list)
        if expected_type == "object":
            return isinstance(val, dict)
        return True
