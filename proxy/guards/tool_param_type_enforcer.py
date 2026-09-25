"""
Agent Tool Parameter Type and Semantic Bounds Enforcer.

Mitigates OWASP LLM08 (Excessive Agency) and LLM05 (Improper Output Handling)
by enforcing strict parameter schema typing, numerical bounds, string lengths,
and enum constraints on agentic tool invocations.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Union


@dataclass
class ToolParamValidationResult:
    is_valid: bool
    is_blocked: bool = False
    violation_code: Optional[str] = None
    details: str = "Tool call parameters valid"
    parameter_name: Optional[str] = None


@dataclass
class ParamConstraint:
    expected_type: type
    required: bool = True
    min_val: Optional[Union[int, float]] = None
    max_val: Optional[Union[int, float]] = None
    min_len: Optional[int] = None
    max_len: Optional[int] = None
    allowed_values: Optional[List[Any]] = None
    regex_pattern: Optional[re.Pattern] = None


class ToolParamTypeEnforcer:
    """
    Validates tool call parameters against registered parameter constraints.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode
        self._schemas: Dict[str, Dict[str, ParamConstraint]] = {}
        self._load_default_tool_schemas()

    def register_schema(self, tool_name: str, schema: Dict[str, ParamConstraint]):
        self._schemas[tool_name] = schema

    def _load_default_tool_schemas(self):
        # Default security constraints for standard agent tools
        self.register_schema("calculator", {
            "expression": ParamConstraint(expected_type=str, required=True, max_len=200, regex_pattern=re.compile(r"^[0-9+\-*/().\s^%]+$"))
        })
        self.register_schema("send_email", {
            "recipient": ParamConstraint(expected_type=str, required=True, max_len=120, regex_pattern=re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
            "subject": ParamConstraint(expected_type=str, required=True, max_len=150),
            "body": ParamConstraint(expected_type=str, required=True, max_len=5000),
            "priority": ParamConstraint(expected_type=str, required=False, allowed_values=["low", "normal", "high"])
        })
        self.register_schema("read_file", {
            "file_path": ParamConstraint(expected_type=str, required=True, max_len=255),
            "max_lines": ParamConstraint(expected_type=int, required=False, min_val=1, max_val=1000)
        })
        self.register_schema("database_query", {
            "query": ParamConstraint(expected_type=str, required=True, max_len=2000),
            "limit": ParamConstraint(expected_type=int, required=False, min_val=1, max_val=500)
        })

    def validate_tool_call(self, tool_name: str, arguments: Union[str, Dict[str, Any]]) -> ToolParamValidationResult:
        if not tool_name:
            return ToolParamValidationResult(is_valid=True)

        # Parse string argument into dictionary if necessary
        if isinstance(arguments, str):
            try:
                args_dict = json.loads(arguments) if arguments.strip() else {}
            except json.JSONDecodeError:
                return ToolParamValidationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="malformed_tool_arguments",
                    details=f"Arguments for tool '{tool_name}' are not valid JSON."
                )
        elif isinstance(arguments, dict):
            args_dict = arguments
        else:
            return ToolParamValidationResult(
                is_valid=False,
                is_blocked=True,
                violation_code="invalid_argument_structure",
                details=f"Arguments for tool '{tool_name}' must be dict or JSON string."
            )

        schema = self._schemas.get(tool_name)
        if not schema:
            if self.strict_mode:
                return ToolParamValidationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="unregistered_tool_schema",
                    details=f"Tool '{tool_name}' has no registered parameter validation schema in strict mode."
                )
            return ToolParamValidationResult(is_valid=True)

        # Check required fields
        for param_name, constraint in schema.items():
            if constraint.required and param_name not in args_dict:
                return ToolParamValidationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="missing_required_parameter",
                    parameter_name=param_name,
                    details=f"Tool '{tool_name}' is missing required parameter '{param_name}'."
                )

        # Check provided fields against constraints
        for param_name, val in args_dict.items():
            constraint = schema.get(param_name)
            if not constraint:
                continue

            # Type check (bool is a subclass of int in Python, handle carefully)
            if constraint.expected_type is int and isinstance(val, bool):
                return ToolParamValidationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="parameter_type_mismatch",
                    parameter_name=param_name,
                    details=f"Parameter '{param_name}' expected int but got bool."
                )

            if not isinstance(val, constraint.expected_type):
                return ToolParamValidationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="parameter_type_mismatch",
                    parameter_name=param_name,
                    details=f"Parameter '{param_name}' expected {constraint.expected_type.__name__} but got {type(val).__name__}."
                )

            # Numerical bounds
            if isinstance(val, (int, float)):
                if constraint.min_val is not None and val < constraint.min_val:
                    return ToolParamValidationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="parameter_bounds_exceeded",
                        parameter_name=param_name,
                        details=f"Parameter '{param_name}' value {val} is below minimum {constraint.min_val}."
                    )
                if constraint.max_val is not None and val > constraint.max_val:
                    return ToolParamValidationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="parameter_bounds_exceeded",
                        parameter_name=param_name,
                        details=f"Parameter '{param_name}' value {val} exceeds maximum {constraint.max_val}."
                    )

            # String/Collection Lengths
            if isinstance(val, (str, list, dict)):
                if constraint.min_len is not None and len(val) < constraint.min_len:
                    return ToolParamValidationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="parameter_length_violation",
                        parameter_name=param_name,
                        details=f"Parameter '{param_name}' length {len(val)} is below minimum length {constraint.min_len}."
                    )
                if constraint.max_len is not None and len(val) > constraint.max_len:
                    return ToolParamValidationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="parameter_length_exceeded",
                        parameter_name=param_name,
                        details=f"Parameter '{param_name}' length {len(val)} exceeds maximum allowed {constraint.max_len}."
                    )

            # Allowed Enum Values
            if constraint.allowed_values is not None:
                if val not in constraint.allowed_values:
                    return ToolParamValidationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="parameter_enum_violation",
                        parameter_name=param_name,
                        details=f"Parameter '{param_name}' value '{val}' not in allowed set {constraint.allowed_values}."
                    )

            # Regex constraints
            if isinstance(val, str) and constraint.regex_pattern is not None:
                if not constraint.regex_pattern.match(val):
                    return ToolParamValidationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="parameter_pattern_violation",
                        parameter_name=param_name,
                        details=f"Parameter '{param_name}' format does not match required security pattern."
                    )

        return ToolParamValidationResult(is_valid=True)
