"""Bidirectional Interceptor Pipeline for LLM Security Guardrails Proxy."""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from proxy.config import ProxySettings, get_settings
from proxy.guards.anomaly_detector import AnomalyDetector
from proxy.guards.canary_generator import DynamicCanaryService
from proxy.guards.anomaly_detector import AnomalyDetector
from proxy.guards.canary_generator import DynamicCanaryService
from proxy.guards.code_sandbox_policy import CodeSandboxPolicyInspector
from proxy.guards.differential_leak_guard import DifferentialLeakGuard
from proxy.guards.hallucination_verifier import HallucinationVerifier
from proxy.guards.homoglyph_detector import HomoglyphDetector
from proxy.guards.mcp_validator import MCPValidator
from proxy.guards.multilingual_guard import MultilingualGuard
from proxy.guards.output_sanitizer import OutputSanitizer
from proxy.guards.pii_sanitizer import PIISanitizer
from proxy.guards.prompt_injection import PromptInjectionGuard
from proxy.guards.rate_limiter import RateLimiter
from proxy.guards.secret_entropy_scanner import SecretEntropyScanner
from proxy.guards.sql_nosql_guard import SqlNoSqlInjectionGuard
from proxy.guards.system_prompt_guard import SystemPromptGuard
from proxy.guards.token_padding_guard import TokenPaddingGuard
from proxy.guards.tool_call_validator import ToolCallValidator
from proxy.guards.watermark_detector import WatermarkClassificationDetector
from proxy.resilience.circuit_breaker import CircuitBreaker
from proxy.telemetry.audit_logger import audit_logger


@dataclass
class PipelineContext:
    """Context state passed between inbound and outbound stages."""
    request_id: str
    client_ip: str
    reversal_map: Dict[str, str] = field(default_factory=dict)
    redacted_entities: Dict[str, int] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)


@dataclass
class InboundPipelineResult:
    """Outcome of inbound pipeline inspection."""
    is_allowed: bool
    sanitized_payload: Optional[Dict[str, Any]] = None
    error_response: Optional[Dict[str, Any]] = None
    context: Optional[PipelineContext] = None


@dataclass
class OutboundPipelineResult:
    """Outcome of outbound pipeline inspection."""
    is_allowed: bool
    sanitized_response: Optional[Dict[str, Any]] = None
    error_response: Optional[Dict[str, Any]] = None


class SecurityPipeline:
    """Coordinates sequential inbound and outbound security guards."""

    def __init__(self, settings: Optional[ProxySettings] = None):
        self.settings = settings or get_settings()
        self.injection_guard = PromptInjectionGuard(threshold=self.settings.INJECTION_THRESHOLD)
        self.pii_sanitizer = PIISanitizer()
        self.system_prompt_guard = SystemPromptGuard(canary_token=self.settings.CANARY_TOKEN)
        self.output_sanitizer = OutputSanitizer()
        self.tool_call_validator = ToolCallValidator()
        self.rate_limiter = RateLimiter(
            requests_per_minute=self.settings.RATE_LIMIT_RPM,
            burst_limit=self.settings.RATE_LIMIT_BURST
        )
        self.homoglyph_detector = HomoglyphDetector()
        self.entropy_scanner = SecretEntropyScanner()
        self.anomaly_detector = AnomalyDetector()
        self.multilingual_guard = MultilingualGuard()
        self.mcp_validator = MCPValidator()
        self.dynamic_canary = DynamicCanaryService(secret_key=self.settings.CANARY_SECRET_KEY)
        self.code_sandbox_policy = CodeSandboxPolicyInspector()
        self.differential_leak_guard = DifferentialLeakGuard(protected_prompts=[self.settings.CANARY_TOKEN])
        self.hallucination_verifier = HallucinationVerifier()
        self.sql_guard = SqlNoSqlInjectionGuard()
        self.token_padding_guard = TokenPaddingGuard()
        self.watermark_detector = WatermarkClassificationDetector()
        self.circuit_breaker = CircuitBreaker()

    def process_inbound(
        self,
        payload: Dict[str, Any],
        request_id: str,
        client_ip: str
    ) -> InboundPipelineResult:
        """Execute inbound security checks on client request."""
        start_time = time.time()
        context = PipelineContext(
            request_id=request_id,
            client_ip=client_ip,
            start_time=start_time
        )

        # 0. Rate Limiting Check (DoS / Brute-force Prevention)
        if self.settings.ENABLE_RATE_LIMITER:
            rate_res = self.rate_limiter.check(client_ip)
            if not rate_res.is_allowed:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=request_id,
                    client_ip=client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="rate_limiter",
                    violation_code="rate_limit_exceeded",
                    details=rate_res.details
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": "rate_limit_exceeded",
                            "message": f"Too Many Requests: {rate_res.details}",
                            "guard": "rate_limiter",
                            "retry_after": rate_res.retry_after_seconds,
                        }
                    },
                    context=context
                )

        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            return InboundPipelineResult(
                is_allowed=False,
                error_response={
                    "error": {
                        "type": "invalid_request_error",
                        "code": "invalid_messages_format",
                        "message": "'messages' field must be a list.",
                    }
                },
                context=context
            )

        sanitized_messages = []
        for msg_idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue

            role = msg.get("role", "user")
            content = msg.get("content", "")

            # If content is a list of blocks (multimodal or text parts)
            text_to_check = ""
            if isinstance(content, str):
                text_to_check = content
            elif isinstance(content, list):
                text_parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(part.get("text", ""))
                text_to_check = " ".join(text_parts)

            # 0b. Token Padding and Delimiter Evasion Guard
            if self.settings.ENABLE_TOKEN_PADDING_GUARD and text_to_check:
                pad_res = self.token_padding_guard.inspect(text_to_check)
                if pad_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="token_padding_guard",
                        violation_code=pad_res.violation_code,
                        details=pad_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": pad_res.violation_code or "token_padding_detected",
                                "message": f"Inbound prompt blocked by Token Padding Guard: {pad_res.details}",
                                "guard": "token_padding_guard",
                            }
                        },
                        context=context
                    )
                text_to_check = pad_res.normalized_content

            # 0c. Sensitive Document Watermark and Classification Guard
            if self.settings.ENABLE_WATERMARK_GUARD and text_to_check:
                wm_res = self.watermark_detector.inspect(text_to_check)
                if wm_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="watermark_detector",
                        violation_code=wm_res.violation_code,
                        details=wm_res.details,
                        metadata={"message_index": msg_idx, "level": wm_res.classification_level}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": wm_res.violation_code or "confidential_watermark_detected",
                                "message": f"Inbound prompt blocked by Watermark Guard: {wm_res.details}",
                                "guard": "watermark_detector",
                            }
                        },
                        context=context
                    )

            # 1. PII Sanitization
            if self.settings.ENABLE_PII_SANITIZER and text_to_check:
                pii_res = self.pii_sanitizer.sanitize(text_to_check)
                if pii_res.redacted_count > 0:
                    text_to_check = pii_res.sanitized_text
                    context.reversal_map.update(pii_res.reversal_map)
                    for ent, count in pii_res.entities_found.items():
                        context.redacted_entities[ent] = context.redacted_entities.get(ent, 0) + count
                        audit_logger.record_pii_redaction(ent, count)

                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="REDACTED",
                        latency_ms=(time.time() - start_time) * 1000,
                        guard="pii_sanitizer",
                        details=f"Redacted {pii_res.redacted_count} entities: {list(pii_res.entities_found.keys())}",
                        metadata={"endpoint": "/v1/chat/completions", "message_index": msg_idx}
                    )

            # 2. Prompt Injection Guard
            if self.settings.ENABLE_PROMPT_INJECTION_GUARD and text_to_check:
                inj_res = self.injection_guard.inspect(text_to_check)
                if inj_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="prompt_injection_guard",
                        violation_code="prompt_injection_detected",
                        details=inj_res.details,
                        metadata={"risk_score": inj_res.score, "message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "prompt_injection_detected",
                                "message": f"Inbound prompt blocked by Prompt Injection Guard: {inj_res.details}",
                                "guard": "prompt_injection_guard",
                                "risk_score": inj_res.score,
                            }
                        },
                        context=context
                    )

            # 3. System Prompt Extraction Guard
            if self.settings.ENABLE_SYSTEM_PROMPT_GUARD and text_to_check:
                sys_res = self.system_prompt_guard.inspect_prompt(text_to_check)
                if sys_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="system_prompt_guard",
                        violation_code=sys_res.violation_code,
                        details=sys_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": sys_res.violation_code or "system_prompt_violation",
                                "message": f"Inbound prompt blocked by System Prompt Guard: {sys_res.details}",
                                "guard": "system_prompt_guard",
                            }
                        },
                        context=context
                    )

            # 3b. Structural Anomaly & Glitch Token Guard
            if self.settings.ENABLE_ANOMALY_GUARD and text_to_check:
                anom_res = self.anomaly_detector.evaluate(text_to_check)
                if anom_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="anomaly_detector",
                        violation_code="structural_anomaly_detected",
                        details=anom_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "structural_anomaly_detected",
                                "message": f"Inbound prompt blocked by Anomaly Detector: {anom_res.details}",
                                "guard": "anomaly_detector",
                            }
                        },
                        context=context
                    )

            # 3c. Homoglyph Spoofing & Leetspeak Guard
            if self.settings.ENABLE_HOMOGLYPH_GUARD and text_to_check:
                homo_res = self.homoglyph_detector.evaluate(text_to_check)
                if homo_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="homoglyph_detector",
                        violation_code="homoglyph_obfuscation_detected",
                        details=homo_res.details,
                        metadata={"message_index": msg_idx, "risk_score": homo_res.score}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "homoglyph_obfuscation_detected",
                                "message": f"Inbound prompt blocked by Homoglyph Guard: {homo_res.details}",
                                "guard": "homoglyph_detector",
                                "risk_score": homo_res.score,
                            }
                        },
                        context=context
                    )

            # 3d. Multilingual Jailbreak Guard
            if self.settings.ENABLE_MULTILINGUAL_GUARD and text_to_check:
                multi_res = self.multilingual_guard.evaluate(text_to_check)
                if multi_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="multilingual_guard",
                        violation_code="multilingual_jailbreak_detected",
                        details=multi_res.details,
                        metadata={"message_index": msg_idx, "languages": multi_res.detected_languages}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "multilingual_jailbreak_detected",
                                "message": f"Inbound prompt blocked by Multilingual Guard: {multi_res.details}",
                                "guard": "multilingual_guard",
                            }
                        },
                        context=context
                    )

            # Reconstruct message with sanitized content
            new_msg = dict(msg)
            if isinstance(content, str):
                new_msg["content"] = text_to_check
            elif isinstance(content, list):
                # If multimodal, update text parts
                new_parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        new_parts.append({"type": "text", "text": text_to_check})
                    else:
                        new_parts.append(part)
                new_msg["content"] = new_parts
            sanitized_messages.append(new_msg)

        # 4. Inbound Tool Call Validation (if client sends tool calls)
        inbound_tool_calls = payload.get("tool_calls")
        if self.settings.ENABLE_TOOL_CALL_VALIDATOR and inbound_tool_calls:
            tool_res = self.tool_call_validator.validate_tool_calls(inbound_tool_calls)
            if not tool_res.is_valid:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=request_id,
                    client_ip=client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="tool_call_validator",
                    violation_code=tool_res.violation_code,
                    details=tool_res.details,
                    metadata={"tool_name": tool_res.tool_name}
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": tool_res.violation_code or "tool_call_validation_failed",
                            "message": f"Inbound tool call blocked: {tool_res.details}",
                            "guard": "tool_call_validator",
                            "tool": tool_res.tool_name,
                        }
                    },
                    context=context
                )

        new_payload = dict(payload)
        new_payload["messages"] = sanitized_messages

        # Log inbound allowed
        audit_logger.log_event(
            request_id=request_id,
            client_ip=client_ip,
            direction="inbound",
            status="ALLOWED",
            latency_ms=(time.time() - start_time) * 1000,
            guard=None,
            details="Passed all inbound guardrails.",
            metadata={"endpoint": "/v1/chat/completions"}
        )

        return InboundPipelineResult(
            is_allowed=True,
            sanitized_payload=new_payload,
            context=context
        )

    def process_outbound(
        self,
        response_json: Dict[str, Any],
        context: PipelineContext
    ) -> OutboundPipelineResult:
        """Execute outbound security checks on LLM response."""
        start_time = time.time()
        choices = response_json.get("choices", [])
        if not choices or not isinstance(choices, list):
            return OutboundPipelineResult(is_allowed=True, sanitized_response=response_json)

        sanitized_choices = []
        for choice in choices:
            msg = choice.get("message", {})
            content = msg.get("content", "") or ""
            tool_calls = msg.get("tool_calls", [])

            # 1. Tool Call Validation for Agentic Output (SSRF / Traversal)
            if self.settings.ENABLE_TOOL_CALL_VALIDATOR and tool_calls:
                tool_res = self.tool_call_validator.validate_tool_calls(tool_calls)
                if not tool_res.is_valid:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="tool_call_validator",
                        violation_code=tool_res.violation_code,
                        details=tool_res.details,
                        metadata={"tool_name": tool_res.tool_name}
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": tool_res.violation_code or "tool_call_validation_failed",
                                "message": f"Agentic tool call blocked by Tool Validator: {tool_res.details}",
                                "guard": "tool_call_validator",
                                "tool": tool_res.tool_name,
                            }
                        }
                    )

            # 1b. MCP Tool Call Validation
            if self.settings.ENABLE_MCP_VALIDATOR and tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    t_args = fn.get("arguments", {})
                    if isinstance(t_args, str):
                        try:
                            import json
                            t_args = json.loads(t_args)
                        except Exception:
                            t_args = {"raw": t_args}
                    mcp_res = self.mcp_validator.validate_tool_call(t_name, t_args if isinstance(t_args, dict) else {})
                    if not mcp_res.is_valid:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=context.request_id,
                            client_ip=context.client_ip,
                            direction="outbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="mcp_validator",
                            violation_code="mcp_policy_violation",
                            details=mcp_res.details,
                            metadata={"tool_name": t_name}
                        )
                        return OutboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": "mcp_policy_violation",
                                    "message": f"Agentic tool call blocked by MCP Validator: {mcp_res.details}",
                                    "guard": "mcp_validator",
                                    "tool": t_name,
                                }
                            }
                        )

            # 1c. SQL / NoSQL Injection Check on Tool Arguments
            if self.settings.ENABLE_SQL_GUARD and tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    t_args = fn.get("arguments", "")
                    if isinstance(t_args, dict):
                        import json
                        t_args = json.dumps(t_args)
                    sql_res = self.sql_guard.inspect(str(t_args))
                    if sql_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=context.request_id,
                            client_ip=context.client_ip,
                            direction="outbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="sql_nosql_guard",
                            violation_code=sql_res.violation_code,
                            details=sql_res.details,
                            metadata={"tool_name": t_name}
                        )
                        return OutboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": sql_res.violation_code,
                                    "message": f"Agentic tool call blocked by SQL/NoSQL Guard: {sql_res.details}",
                                    "guard": "sql_nosql_guard",
                                    "tool": t_name,
                                }
                            }
                        )

            # 1d. AST Code Sandbox Policy Check
            if self.settings.ENABLE_AST_SANDBOX_GUARD and tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "").lower()
                    if any(term in t_name for term in ["code", "python", "exec", "eval", "script", "run"]):
                        t_args = fn.get("arguments", "")
                        code_str = ""
                        if isinstance(t_args, dict):
                            code_str = t_args.get("code") or t_args.get("script") or str(t_args)
                        elif isinstance(t_args, str):
                            try:
                                import json
                                parsed_args = json.loads(t_args)
                                if isinstance(parsed_args, dict):
                                    code_str = parsed_args.get("code") or parsed_args.get("script") or t_args
                                else:
                                    code_str = t_args
                            except Exception:
                                code_str = t_args
                        ast_res = self.code_sandbox_policy.inspect(code_str)
                        if ast_res.is_blocked:
                            latency = (time.time() - start_time) * 1000
                            audit_logger.log_event(
                                request_id=context.request_id,
                                client_ip=context.client_ip,
                                direction="outbound",
                                status="BLOCKED",
                                latency_ms=latency,
                                guard="code_sandbox_policy",
                                violation_code=ast_res.violation_code,
                                details=ast_res.details,
                                metadata={"tool_name": fn.get("name", "")}
                            )
                            return OutboundPipelineResult(
                                is_allowed=False,
                                error_response={
                                    "error": {
                                        "type": "security_policy_violation",
                                        "code": ast_res.violation_code,
                                        "message": f"Agentic tool call blocked by Code Sandbox Policy: {ast_res.details}",
                                        "guard": "code_sandbox_policy",
                                        "tool": fn.get("name", ""),
                                    }
                                }
                            )

            # 2. Canary Leak Check
            if self.settings.ENABLE_SYSTEM_PROMPT_GUARD and content:
                sys_res = self.system_prompt_guard.inspect_completion(content)
                if sys_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="system_prompt_guard",
                        violation_code=sys_res.violation_code,
                        details=sys_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": sys_res.violation_code or "canary_token_leak",
                                "message": f"Outbound completion blocked: {sys_res.details}",
                                "guard": "system_prompt_guard",
                            }
                        }
                    )

                # 2b. Dynamic Cryptographic Canary Check
                canary_res = self.dynamic_canary.inspect_text(content)
                if canary_res.is_leaked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="dynamic_canary_guard",
                        violation_code="dynamic_canary_token_leak",
                        details=canary_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "dynamic_canary_token_leak",
                                "message": f"Outbound completion blocked by Dynamic Canary Guard: {canary_res.details}",
                                "guard": "dynamic_canary_guard",
                            }
                        }
                    )

            # 3. Output Sanitizer (Hazardous commands & secrets)
            if self.settings.ENABLE_OUTPUT_SANITIZER and content:
                out_res = self.output_sanitizer.inspect(content)
                if out_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="output_sanitizer",
                        violation_code=out_res.violation_code,
                        details=out_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": out_res.violation_code or "insecure_output_detected",
                                "message": f"Outbound response blocked by Output Sanitizer: {out_res.details}",
                                "guard": "output_sanitizer",
                            }
                        }
                    )

            # 3b. High-Entropy Secret Scanner
            if self.settings.ENABLE_ENTROPY_SCANNER and content:
                entropy_res = self.entropy_scanner.evaluate(content)
                if entropy_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="secret_entropy_scanner",
                        violation_code="secret_entropy_leak_detected",
                        details=entropy_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "secret_entropy_leak_detected",
                                "message": f"Outbound response blocked by Secret Entropy Scanner: {entropy_res.details}",
                                "guard": "secret_entropy_scanner",
                            }
                        }
                    )

            # 3c. Differential N-Gram System Prompt Leakage Check
            if self.settings.ENABLE_DIFFERENTIAL_LEAK_GUARD and content:
                diff_res = self.differential_leak_guard.inspect(content)
                if diff_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="differential_leak_guard",
                        violation_code=diff_res.violation_code,
                        details=diff_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": diff_res.violation_code or "differential_prompt_leak",
                                "message": f"Outbound completion blocked by Differential Leak Guard: {diff_res.details}",
                                "guard": "differential_leak_guard",
                            }
                        }
                    )

            # 3d. Outbound Sensitive Document Watermark Check
            if self.settings.ENABLE_WATERMARK_GUARD and content:
                wm_res = self.watermark_detector.inspect(content)
                if wm_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="watermark_detector",
                        violation_code=wm_res.violation_code,
                        details=wm_res.details,
                        metadata={"level": wm_res.classification_level}
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": wm_res.violation_code,
                                "message": f"Outbound completion blocked by Watermark Guard: {wm_res.details}",
                                "guard": "watermark_detector",
                            }
                        }
                    )

            # 4. Optional De-Anonymization (restore PII tokens in response if configured)
            if self.settings.DE_ANONYMIZE_OUTPUT and context.reversal_map and content:
                content = self.pii_sanitizer.de_anonymize(content, context.reversal_map)

            new_choice = dict(choice)
            new_msg = dict(msg)
            new_msg["content"] = content
            new_choice["message"] = new_msg
            sanitized_choices.append(new_choice)

        new_response = dict(response_json)
        new_response["choices"] = sanitized_choices

        audit_logger.log_event(
            request_id=context.request_id,
            client_ip=context.client_ip,
            direction="outbound",
            status="ALLOWED",
            latency_ms=(time.time() - start_time) * 1000,
            guard=None,
            details="Passed all outbound security hygiene checks.",
            metadata={"choices_count": len(sanitized_choices)}
        )

        return OutboundPipelineResult(
            is_allowed=True,
            sanitized_response=new_response
        )
