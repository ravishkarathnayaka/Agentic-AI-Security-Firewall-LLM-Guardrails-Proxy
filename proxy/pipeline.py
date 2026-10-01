"""Bidirectional Interceptor Pipeline for LLM Security Guardrails Proxy."""

import json
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
from proxy.guards.canary_redactor import CanaryLeakScrubber
from proxy.guards.command_injection_guard import CommandInjectionGuard
from proxy.guards.context_exfiltration_guard import ContextExfiltrationGuard
from proxy.guards.goal_drift_detector import GoalDriftDetector
from proxy.guards.homoglyph_detector import HomoglyphDetector
from proxy.guards.json_schema_enforcer import StructuredOutputEnforcer
from proxy.guards.mcp_validator import MCPValidator
from proxy.guards.memory_poisoning_guard import MemoryPoisoningGuard
from proxy.guards.multilingual_guard import MultilingualGuard
from proxy.guards.nested_unpack_guard import NestedUnpackGuard
from proxy.guards.network_guard import NetworkPerimeterGuard
from proxy.guards.output_sanitizer import OutputSanitizer
from proxy.guards.phonetic_leetspeak_guard import PhoneticLeetspeakGuard
from proxy.guards.pii_sanitizer import PIISanitizer
from proxy.guards.pii_synthetic_generator import SyntheticPIIGenerator
from proxy.guards.prompt_injection import PromptInjectionGuard
from proxy.guards.rate_limiter import RateLimiter
from proxy.guards.recursion_budget_guard import RecursionBudgetGuard
from proxy.guards.secret_entropy_scanner import SecretEntropyScanner
from proxy.guards.semantic_loop_breaker import SemanticLoopBreaker
from proxy.guards.sql_nosql_guard import SqlNoSqlInjectionGuard
from proxy.guards.system_prompt_guard import SystemPromptGuard
from proxy.guards.token_padding_guard import TokenPaddingGuard
from proxy.guards.token_smuggling_guard import TokenSmugglingGuard
from proxy.guards.tool_call_validator import ToolCallValidator
from proxy.guards.agent_tool_rbac_guard import AgentToolRBACGuard, AgentRole
from proxy.guards.agent_velocity_guard import AgentVelocityGuard
from proxy.guards.bidi_override_guard import BidiOverrideGuard
from proxy.guards.context_bomb_guard import ContextBombGuard
from proxy.guards.deserialization_guard import DeserializationGuard
from proxy.guards.tool_param_type_enforcer import ToolParamTypeEnforcer
from proxy.guards.watermark_detector import WatermarkClassificationDetector
from proxy.guards.canary_reflection_attenuation_guard import CanaryReflectionAttenuationGuard
from proxy.guards.shadow_demonstration_guard import ShadowDemonstrationGuard
from proxy.guards.egress_domain_allowlist_guard import EgressDomainAllowlistGuard
from proxy.guards.param_redos_guard import ParamReDoSGuard
from proxy.guards.session_replay_guard import SessionAntiReplayGuard
from proxy.guards.epistemic_uncertainty_guard import EpistemicUncertaintyGuard
from proxy.guards.capability_token_guard import CapabilityTokenGuard
from proxy.guards.rag_poison_guard import RAGPoisonGuard
from proxy.guards.decompression_bomb_guard import DecompressionBombGuard
from proxy.guards.semantic_similarity_guard import SemanticSimilarityGuard
from proxy.guards.param_differential_guard import ParamDifferentialGuard
from proxy.guards.agent_attestation_guard import AgentAttestationGuard
from proxy.guards.state_rollback_guard import StateRollbackGuard
from proxy.guards.cost_quota_guard import CostQuotaGuard
from proxy.guards.mutation_fuzz_guard import MutationFuzzGuard
from proxy.guards.tenant_isolation_guard import TenantIsolationGuard
from proxy.guards.delegation_depth_guard import DelegationDepthGuard
from proxy.guards.stego_separator_guard import StegoSeparatorGuard
from proxy.guards.schema_mutation_guard import SchemaMutationGuard
from proxy.guards.proof_of_execution_guard import ProofOfExecutionGuard
from proxy.guards.feedback_loop_guard import FeedbackLoopGuard
from proxy.guards.token_entropy_guard import TokenEntropyGuard
from proxy.guards.capability_lease_guard import CapabilityLeaseGuard
from proxy.guards.obfuscation_evasion_guard import ObfuscationEvasionGuard
from proxy.guards.argument_sanitizer_guard import ToolCallArgumentSanitizerGuard
from proxy.guards.plan_integrity_guard import AgentPlanIntegrityGuard
from proxy.guards.cross_context_guard import CrossContextContaminationGuard
from proxy.guards.model_inversion_guard import ModelInversionDefenseGuard
from proxy.guards.semantic_boundary_guard import IndirectInjectionSemanticBoundaryGuard
from proxy.guards.egress_payload_sanitizer_guard import AgentEgressPayloadSanitizerGuard
from proxy.guards.rate_burst_governor_guard import AdaptiveRateBurstGovernorGuard
from proxy.guards.prompt_fingerprint_guard import PromptFingerprintCacheGuard
from proxy.guards.schema_validator_guard import StructuredOutputSchemaValidatorGuard
from proxy.guards.tool_concurrency_guard import AgentToolConcurrencyGuard
from proxy.guards.context_drift_guard import ContextDriftGuard
from proxy.guards.byzantine_consensus_guard import ByzantineConsensusGuard
from proxy.guards.action_idempotency_guard import AgentActionIdempotencyGuard
from proxy.guards.sparse_token_guard import SparseTokenSteganographyGuard
from proxy.guards.canary_rotation_guard import CanaryRotationGuard
from proxy.guards.task_ttl_guard import AgentTaskTTLGuard
from proxy.guards.tool_return_quarantine_guard import ToolReturnQuarantineGuard
from proxy.guards.sidechannel_timing_guard import SidechannelTimingGuard
from proxy.guards.multi_tenant_sandbox_jail_guard import MultiTenantSandboxJailGuard
from proxy.guards.agent_reflection_loop_guard import AgentReflectionLoopGuard
from proxy.guards.subagent_privilege_escalation_guard import SubagentPrivilegeEscalationGuard
from proxy.guards.semantic_cache_poisoning_guard import SemanticCachePoisoningGuard
from proxy.guards.cross_tenant_token_bleed_guard import CrossTenantTokenBleedGuard
from proxy.guards.adaptive_rate_burst_guard import AdaptiveRateBurstGuard
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
        self.network_guard = NetworkPerimeterGuard()
        self.nested_unpack_guard = NestedUnpackGuard()
        self.json_schema_enforcer = StructuredOutputEnforcer()
        self.goal_drift_detector = GoalDriftDetector()
        self.synthetic_pii_generator = SyntheticPIIGenerator()
        self.phonetic_leet_guard = PhoneticLeetspeakGuard()
        self.command_injection_guard = CommandInjectionGuard()
        self.token_smuggling_guard = TokenSmugglingGuard()
        self.recursion_budget_guard = RecursionBudgetGuard()
        self.canary_scrubber = CanaryLeakScrubber(static_tokens=[self.settings.CANARY_TOKEN])
        self.context_exfil_guard = ContextExfiltrationGuard()
        self.tool_param_enforcer = ToolParamTypeEnforcer()
        self.memory_poisoning_guard = MemoryPoisoningGuard()
        self.semantic_loop_breaker = SemanticLoopBreaker()
        self.agent_tool_rbac_guard = AgentToolRBACGuard()
        self.bidi_override_guard = BidiOverrideGuard()
        self.deserialization_guard = DeserializationGuard()
        self.context_bomb_guard = ContextBombGuard()
        self.agent_velocity_guard = AgentVelocityGuard()
        self.shadow_demo_guard = ShadowDemonstrationGuard()
        self.egress_allowlist_guard = EgressDomainAllowlistGuard()
        self.param_redos_guard = ParamReDoSGuard()
        self.session_replay_guard = SessionAntiReplayGuard()
        self.epistemic_guard = EpistemicUncertaintyGuard()
        self.canary_attenuation_guard = CanaryReflectionAttenuationGuard(canary_tokens=[self.settings.CANARY_TOKEN])
        self.capability_token_guard = CapabilityTokenGuard(enforce_capability_tokens=self.settings.ENABLE_CAPABILITY_TOKEN_GUARD)
        self.rag_poison_guard = RAGPoisonGuard()
        self.decompression_bomb_guard = DecompressionBombGuard()
        self.semantic_similarity_guard = SemanticSimilarityGuard()
        self.param_differential_guard = ParamDifferentialGuard()
        self.agent_attestation_guard = AgentAttestationGuard(enforce_attestation=self.settings.ENABLE_AGENT_ATTESTATION_GUARD)
        self.state_rollback_guard = StateRollbackGuard()
        self.cost_quota_guard = CostQuotaGuard(enforce_quotas=self.settings.ENABLE_COST_QUOTA_GUARD)
        self.mutation_fuzz_guard = MutationFuzzGuard(block_on_mutation=self.settings.ENABLE_MUTATION_FUZZ_GUARD)
        self.tenant_isolation_guard = TenantIsolationGuard(enforce_isolation=self.settings.ENABLE_TENANT_ISOLATION_GUARD)
        self.delegation_depth_guard = DelegationDepthGuard(block_on_breach=self.settings.ENABLE_DELEGATION_DEPTH_GUARD)
        self.stego_separator_guard = StegoSeparatorGuard(block_on_covert_data=self.settings.ENABLE_STEGO_SEPARATOR_GUARD)
        self.schema_mutation_guard = SchemaMutationGuard(enabled=self.settings.ENABLE_SCHEMA_MUTATION_GUARD)
        self.proof_of_execution_guard = ProofOfExecutionGuard(enabled=self.settings.ENABLE_PROOF_OF_EXECUTION_GUARD)
        self.feedback_loop_guard = FeedbackLoopGuard()
        self.token_entropy_guard = TokenEntropyGuard()
        self.capability_lease_guard = CapabilityLeaseGuard()
        self.obfuscation_evasion_guard = ObfuscationEvasionGuard()
        self.argument_sanitizer_guard = ToolCallArgumentSanitizerGuard()
        self.plan_integrity_guard = AgentPlanIntegrityGuard()
        self.cross_context_guard = CrossContextContaminationGuard()
        self.model_inversion_guard = ModelInversionDefenseGuard()
        self.semantic_boundary_guard = IndirectInjectionSemanticBoundaryGuard()
        self.egress_sanitizer_guard = AgentEgressPayloadSanitizerGuard()
        self.rate_burst_governor = AdaptiveRateBurstGovernorGuard()
        self.prompt_fingerprint_guard = PromptFingerprintCacheGuard()
        self.schema_validator_guard = StructuredOutputSchemaValidatorGuard()
        self.tool_concurrency_guard = AgentToolConcurrencyGuard()
        self.context_drift_guard = ContextDriftGuard()
        self.byzantine_consensus_guard = ByzantineConsensusGuard()
        self.action_idempotency_guard = AgentActionIdempotencyGuard()
        self.sparse_token_guard = SparseTokenSteganographyGuard()
        self.canary_rotation_guard = CanaryRotationGuard()
        self.task_ttl_guard = AgentTaskTTLGuard()
        self.tool_return_quarantine_guard = ToolReturnQuarantineGuard()
        self.sidechannel_timing_guard = SidechannelTimingGuard()
        self.sandbox_jail_guard = MultiTenantSandboxJailGuard()
        self.reflection_loop_guard = AgentReflectionLoopGuard()
        self.subagent_privilege_guard = SubagentPrivilegeEscalationGuard()
        self.cache_poisoning_guard = SemanticCachePoisoningGuard()
        self.token_bleed_guard = CrossTenantTokenBleedGuard()
        self.adaptive_rate_burst_guard = AdaptiveRateBurstGuard()
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

        # -1. Network Perimeter & CIDR Blocklist Check
        if self.settings.ENABLE_NETWORK_PERIMETER_GUARD and client_ip:
            is_net_blocked, net_reason = self.network_guard.check_ip(client_ip)
            if is_net_blocked:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=request_id,
                    client_ip=client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="network_perimeter_guard",
                    violation_code="disallowed_cidr_subnet",
                    details=net_reason
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": "disallowed_cidr_subnet",
                            "message": f"Inbound request blocked by Network Perimeter Guard: {net_reason}",
                            "guard": "network_perimeter_guard",
                        }
                    },
                    context=context
                )

        # -0.5. Instantaneous Prompt Fingerprint Cache Check
        if self.settings.ENABLE_PROMPT_FINGERPRINT_GUARD:
            for m in payload.get("messages", []):
                if isinstance(m, dict) and isinstance(m.get("content"), str):
                    fp_res = self.prompt_fingerprint_guard.check_fingerprint(m["content"])
                    if fp_res.is_match:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="prompt_fingerprint_guard",
                            violation_code=fp_res.violation_code or "known_attack_fingerprint_match",
                            details=fp_res.details
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": fp_res.violation_code or "known_attack_fingerprint_match",
                                    "message": f"Inbound prompt blocked by Fingerprint Guard: {fp_res.details}",
                                    "guard": "prompt_fingerprint_guard",
                                }
                            },
                            context=context
                        )

        # -0.2. Adaptive Rate Burst Governor Guard
        if self.settings.ENABLE_RATE_BURST_GOVERNOR_GUARD and client_ip:
            gov_res = self.rate_burst_governor.consume(client_ip)
            if not gov_res.is_allowed:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=request_id,
                    client_ip=client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="rate_burst_governor_guard",
                    violation_code=gov_res.violation_code or "rate_burst_quota_exceeded",
                    details=gov_res.details
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": gov_res.violation_code or "rate_burst_quota_exceeded",
                            "message": f"Inbound request blocked by Rate Governor Guard: {gov_res.details}",
                            "guard": "rate_burst_governor_guard",
                            "retry_after": gov_res.retry_after_sec
                        }
                    },
                    context=context
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

        # 0b. Agent Subagent Delegation Depth Ceiling Guard
        if self.settings.ENABLE_DELEGATION_DEPTH_GUARD and ("delegation_chain" in payload or "delegation_depth" in payload):
            chain = payload.get("delegation_chain")
            if chain is None and "delegation_depth" in payload:
                chain = [f"agent_{i}" for i in range(payload["delegation_depth"])]
            if chain:
                del_res = self.delegation_depth_guard.inspect_chain(chain)
                if del_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="delegation_depth_guard",
                        violation_code=del_res.violation_code or "delegation_depth_exceeded",
                        details=del_res.details,
                        metadata={"depth": del_res.current_depth, "max_depth": del_res.max_depth}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": del_res.violation_code or "delegation_depth_exceeded",
                                "message": f"Inbound delegation blocked by Delegation Depth Guard: {del_res.details}",
                                "guard": "delegation_depth_guard",
                            }
                        },
                        context=context
                    )

        # 0c. Multi-Tenant Workspace & Security Zone Guard
        if self.settings.ENABLE_TENANT_ISOLATION_GUARD and ("tenant_id" in payload or "target_workspace" in payload or "requested_zone" in payload):
            caller_tenant = payload.get("tenant_id") or payload.get("tenant") or "default"
            target_zone = payload.get("requested_zone") or payload.get("target_workspace") or payload.get("workspace_id")
            if target_zone:
                t_res = self.tenant_isolation_guard.validate_zone_access(caller_tenant, target_zone)
                if t_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="tenant_isolation_guard",
                        violation_code=t_res.violation_code or "cross_tenant_access_denied",
                        details=t_res.details,
                        metadata={"caller_tenant": caller_tenant, "target_zone": target_zone}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": t_res.violation_code or "cross_tenant_access_denied",
                                "message": f"Inbound access blocked by Tenant Isolation Guard: {t_res.details}",
                                "guard": "tenant_isolation_guard",
                            }
                        },
                        context=context
                    )

        # 0d. Agent Cost Quota & Tool Rate Limiter Guard
        if self.settings.ENABLE_COST_QUOTA_GUARD and ("agent_id" in payload or "session_id" in payload):
            session_id = payload.get("session_id") or payload.get("agent_id") or client_ip or "default_session"
            sample_prompt = ""
            for m in payload.get("messages", []):
                if isinstance(m, dict) and isinstance(m.get("content"), str):
                    sample_prompt += m.get("content") + " "
            cq_res = self.cost_quota_guard.check_inbound_budget(session_id, sample_prompt)
            if cq_res.is_blocked:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=request_id,
                    client_ip=client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="cost_quota_guard",
                    violation_code=cq_res.violation_code or "session_budget_exceeded",
                    details=cq_res.details,
                    metadata={"session_id": session_id}
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": cq_res.violation_code or "session_budget_exceeded",
                            "message": f"Inbound request blocked by Cost Quota Guard: {cq_res.details}",
                            "guard": "cost_quota_guard",
                        }
                    },
                    context=context
                )

        # 0e. Agent Plan Integrity Guard
        if self.settings.ENABLE_PLAN_INTEGRITY_GUARD and ("plan_steps" in payload or "execution_plan" in payload):
            plan = payload.get("plan_steps") or payload.get("execution_plan", [])
            if isinstance(plan, list):
                plan_res = self.plan_integrity_guard.validate_plan(plan)
                if not plan_res.is_valid:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="plan_integrity_guard",
                        violation_code=plan_res.violation_code or "plan_integrity_violation",
                        details=plan_res.details
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": plan_res.violation_code or "plan_integrity_violation",
                                "message": f"Inbound plan blocked by Plan Integrity Guard: {plan_res.details}",
                                "guard": "plan_integrity_guard",
                            }
                        },
                        context=context
                    )

        # Byzantine Consensus Guard
        if self.settings.ENABLE_BYZANTINE_CONSENSUS_GUARD and "agent_proposals" in payload:
            proposals = payload.get("agent_proposals", [])
            task_id = payload.get("task_id", context.request_id)
            byz_res = self.byzantine_consensus_guard.evaluate_proposals(task_id, proposals)
            if not byz_res.is_allowed:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=request_id,
                    client_ip=client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="byzantine_consensus_guard",
                    violation_code=byz_res.violation_code or "byzantine_consensus_failure",
                    details=byz_res.details
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": byz_res.violation_code or "byzantine_consensus_failure",
                            "message": f"Inbound action blocked by Byzantine Consensus Guard: {byz_res.details}",
                            "guard": "byzantine_consensus_guard",
                        }
                    },
                    context=context
                )

        # Context Window Drift & Epistemic Divergence Guard
        if self.settings.ENABLE_CONTEXT_DRIFT_GUARD and ("session_id" in payload or "messages" in payload):
            drift_sess = payload.get("session_id", client_ip or "default_session")
            drift_msgs = payload.get("messages", [])
            if isinstance(drift_msgs, list) and len(drift_msgs) > 0:
                drift_res = None
                for m in drift_msgs:
                    if isinstance(m, dict) and isinstance(m.get("content"), str) and m.get("content").strip():
                        drift_res = self.context_drift_guard.record_and_evaluate_turn(drift_sess, m["content"])
                        if drift_res.is_blocked:
                            break
                if drift_res and drift_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="context_drift_guard",
                        violation_code=drift_res.violation_code or "context_window_drift_detected",
                        details=drift_res.details
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": drift_res.violation_code or "context_window_drift_detected",
                                "message": f"Inbound session blocked by Context Drift Guard: {drift_res.details}",
                                "guard": "context_drift_guard",
                            }
                        },
                        context=context
                    )

        # Agent Sub-Task TTL & Orphan Killer Guard
        if self.settings.ENABLE_TASK_TTL_GUARD and "task_id" in payload:
            task_id = payload.get("task_id")
            if task_id:
                ttl_res = self.task_ttl_guard.validate_task_execution(task_id)
                if ttl_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="task_ttl_guard",
                        violation_code=ttl_res.violation_code or "task_ttl_violation",
                        details=ttl_res.details
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": ttl_res.violation_code or "task_ttl_violation",
                                "message": f"Inbound task blocked by Task TTL Guard: {ttl_res.details}",
                                "guard": "task_ttl_guard",
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

            # -0.8. Tool Return Payload Quarantine Guard
            if self.settings.ENABLE_TOOL_RETURN_QUARANTINE_GUARD and role == "tool" and text_to_check:
                tool_name = msg.get("name", "tool_observation")
                quar_res = self.tool_return_quarantine_guard.inspect_and_quarantine(tool_name, text_to_check)
                if quar_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="tool_return_quarantine_guard",
                        violation_code=quar_res.violation_code or "tool_return_indirect_injection_blocked",
                        details=quar_res.details,
                        metadata={"tool_name": tool_name}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": quar_res.violation_code or "tool_return_indirect_injection_blocked",
                                "message": f"Tool output blocked by Quarantine Guard: {quar_res.details}",
                                "guard": "tool_return_quarantine_guard",
                            }
                        },
                        context=context
                    )
                if quar_res.is_quarantined and quar_res.sanitized_output is not None:
                    text_to_check = str(quar_res.sanitized_output)

            # 00. Unicode Bidirectional (Bidi) Override & Visual Spoofing Check
            if self.settings.ENABLE_BIDI_OVERRIDE_GUARD and text_to_check:
                bidi_res = self.bidi_override_guard.inspect_text(text_to_check)
                if bidi_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="bidi_override_guard",
                        violation_code=bidi_res.violation_code,
                        details=bidi_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": bidi_res.violation_code,
                                "message": f"Inbound prompt blocked by Bidi Override Guard: {bidi_res.details}",
                                "guard": "bidi_override_guard",
                            }
                        },
                        context=context
                    )
                if bidi_res.sanitized_text:
                    text_to_check = bidi_res.sanitized_text

            # 0a. Token Smuggling and Zero-Width Steganography Check
            if self.settings.ENABLE_TOKEN_SMUGGLING_GUARD and text_to_check:
                smug_res = self.token_smuggling_guard.inspect(text_to_check)
                if smug_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="token_smuggling_guard",
                        violation_code=smug_res.violation_code,
                        details=smug_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": smug_res.violation_code or "zero_width_smuggling_detected",
                                "message": f"Inbound prompt blocked by Token Smuggling Guard: {smug_res.details}",
                                "guard": "token_smuggling_guard",
                            }
                        },
                        context=context
                    )
                text_to_check = smug_res.sanitized_text

            # 0a.2. Prompt Compression & Sparse Token Steganography Guard
            if self.settings.ENABLE_SPARSE_TOKEN_GUARD and text_to_check:
                sparse_res = self.sparse_token_guard.analyze(text_to_check)
                if sparse_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="sparse_token_guard",
                        violation_code=sparse_res.violation_code or "steganographic_invisible_token_detected",
                        details=sparse_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": sparse_res.violation_code or "steganographic_invisible_token_detected",
                                "message": f"Inbound prompt blocked by Sparse Token Guard: {sparse_res.details}",
                                "guard": "sparse_token_guard",
                            }
                        },
                        context=context
                    )
                text_to_check = sparse_res.sanitized_text

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

            # 1e. Nested Unpack Obfuscation Check
            if self.settings.ENABLE_NESTED_UNPACK_GUARD and text_to_check:
                unpacked_variants = self.nested_unpack_guard.unpack_all_variants(text_to_check)
                for variant in unpacked_variants:
                    if variant != text_to_check:
                        # 1. Prompt Injection
                        nested_inj = self.injection_guard.inspect(variant)
                        if nested_inj.is_blocked:
                            latency = (time.time() - start_time) * 1000
                            audit_logger.log_event(
                                request_id=request_id,
                                client_ip=client_ip,
                                direction="inbound",
                                status="BLOCKED",
                                latency_ms=latency,
                                guard="nested_unpack_guard",
                                violation_code="nested_injection_detected",
                                details=f"Obfuscated injection detected after unpacking: {nested_inj.details}",
                                metadata={"risk_score": nested_inj.score, "message_index": msg_idx}
                            )
                            return InboundPipelineResult(
                                is_allowed=False,
                                error_response={
                                    "error": {
                                        "type": "security_policy_violation",
                                        "code": "nested_injection_detected",
                                        "message": f"Inbound prompt blocked by Nested Unpack Guard: {nested_inj.details}",
                                        "guard": "nested_unpack_guard",
                                        "risk_score": nested_inj.score,
                                    }
                                },
                                context=context
                            )

                        # 2. Goal Drift & Persona Hijacking
                        if self.settings.ENABLE_GOAL_DRIFT_DETECTOR:
                            d_det, d_sc, d_rs = self.goal_drift_detector.inspect_prompt(variant)
                            if d_det:
                                latency = (time.time() - start_time) * 1000
                                audit_logger.log_event(
                                    request_id=request_id,
                                    client_ip=client_ip,
                                    direction="inbound",
                                    status="BLOCKED",
                                    latency_ms=latency,
                                    guard="nested_unpack_guard",
                                    violation_code="nested_goal_drift_detected",
                                    details=f"Obfuscated goal drift detected after unpacking: {d_rs}",
                                    metadata={"risk_score": d_sc, "message_index": msg_idx}
                                )
                                return InboundPipelineResult(
                                    is_allowed=False,
                                    error_response={
                                        "error": {
                                            "type": "security_policy_violation",
                                            "code": "nested_goal_drift_detected",
                                            "message": f"Inbound prompt blocked by Nested Unpack Guard: {d_rs}",
                                            "guard": "nested_unpack_guard",
                                            "risk_score": d_sc,
                                        }
                                    },
                                    context=context
                                )

                        # 3. SQL / NoSQL Injection
                        if self.settings.ENABLE_SQL_GUARD:
                            sql_sub = self.sql_guard.inspect(variant)
                            if sql_sub.is_blocked:
                                latency = (time.time() - start_time) * 1000
                                audit_logger.log_event(
                                    request_id=request_id,
                                    client_ip=client_ip,
                                    direction="inbound",
                                    status="BLOCKED",
                                    latency_ms=latency,
                                    guard="nested_unpack_guard",
                                    violation_code="nested_sql_injection_detected",
                                    details=f"Obfuscated SQL injection detected after unpacking: {sql_sub.details}",
                                    metadata={"message_index": msg_idx}
                                )
                                return InboundPipelineResult(
                                    is_allowed=False,
                                    error_response={
                                        "error": {
                                            "type": "security_policy_violation",
                                            "code": "nested_sql_injection_detected",
                                            "message": f"Inbound prompt blocked by Nested Unpack Guard: {sql_sub.details}",
                                            "guard": "nested_unpack_guard",
                                        }
                                    },
                                    context=context
                                )

                        # 4. System Prompt Extraction
                        if self.settings.ENABLE_SYSTEM_PROMPT_GUARD:
                            sys_sub = self.system_prompt_guard.inspect_prompt(variant)
                            if sys_sub.is_blocked:
                                latency = (time.time() - start_time) * 1000
                                audit_logger.log_event(
                                    request_id=request_id,
                                    client_ip=client_ip,
                                    direction="inbound",
                                    status="BLOCKED",
                                    latency_ms=latency,
                                    guard="nested_unpack_guard",
                                    violation_code="nested_system_prompt_leak_detected",
                                    details=f"Obfuscated system extraction detected after unpacking: {sys_sub.details}",
                                    metadata={"message_index": msg_idx}
                                )
                                return InboundPipelineResult(
                                    is_allowed=False,
                                    error_response={
                                        "error": {
                                            "type": "security_policy_violation",
                                            "code": "nested_system_prompt_leak_detected",
                                            "message": f"Inbound prompt blocked by Nested Unpack Guard: {sys_sub.details}",
                                            "guard": "nested_unpack_guard",
                                        }
                                    },
                                    context=context
                                )

                        # 5. Dangerous scripts or SSRF URLs
                        if "<script" in variant.lower() or "javascript:" in variant.lower():
                            latency = (time.time() - start_time) * 1000
                            audit_logger.log_event(
                                request_id=request_id,
                                client_ip=client_ip,
                                direction="inbound",
                                status="BLOCKED",
                                latency_ms=latency,
                                guard="nested_unpack_guard",
                                violation_code="nested_xss_detected",
                                details="Obfuscated script injection detected after unpacking",
                                metadata={"message_index": msg_idx}
                            )
                            return InboundPipelineResult(
                                is_allowed=False,
                                error_response={
                                    "error": {
                                        "type": "security_policy_violation",
                                        "code": "nested_xss_detected",
                                        "message": "Inbound prompt blocked by Nested Unpack Guard: Obfuscated script detected.",
                                        "guard": "nested_unpack_guard",
                                    }
                                },
                                context=context
                            )

            # 1f. Phonetic & Leetspeak Deobfuscation Check
            if self.settings.ENABLE_PHONETIC_LEET_GUARD and text_to_check:
                norm_leet, n_leet = self.phonetic_leet_guard.normalize(text_to_check)
                if n_leet > 0 and norm_leet != text_to_check:
                    leet_inj = self.injection_guard.inspect(norm_leet)
                    if leet_inj.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="phonetic_leetspeak_guard",
                            violation_code="phonetic_leetspeak_injection",
                            details=f"Phonetic leetspeak evasion detected: {leet_inj.details}",
                            metadata={"risk_score": leet_inj.score, "message_index": msg_idx}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": "phonetic_leetspeak_injection",
                                    "message": f"Inbound prompt blocked by Phonetic Leet Guard: {leet_inj.details}",
                                    "guard": "phonetic_leetspeak_guard",
                                    "risk_score": leet_inj.score,
                                }
                            },
                            context=context
                        )
                    d_leet, _, d_r_leet = self.goal_drift_detector.inspect_prompt(norm_leet)
                    if d_leet:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="phonetic_leetspeak_guard",
                            violation_code="phonetic_goal_drift_detected",
                            details=f"Phonetic goal drift detected: {d_r_leet}",
                            metadata={"message_index": msg_idx}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": "phonetic_goal_drift_detected",
                                    "message": f"Inbound prompt blocked by Phonetic Leet Guard: {d_r_leet}",
                                    "guard": "phonetic_leetspeak_guard",
                                }
                            },
                            context=context
                        )

            # 1f. Context Exfiltration & Covert Channel Guard
            if self.settings.ENABLE_CONTEXT_EXFILTRATION_GUARD and text_to_check:
                exfil_res = self.context_exfil_guard.inspect_text(text_to_check)
                if exfil_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="context_exfiltration_guard",
                        violation_code=exfil_res.violation_code,
                        details=exfil_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": exfil_res.violation_code,
                                "message": f"Inbound prompt blocked by Context Exfiltration Guard: {exfil_res.details}",
                                "guard": "context_exfiltration_guard",
                            }
                        },
                        context=context
                    )

            # 1g. Agent Persistent Memory Poisoning Guard
            if self.settings.ENABLE_MEMORY_POISONING_GUARD and text_to_check:
                mem_res = self.memory_poisoning_guard.inspect_memory_payload(text_to_check)
                if mem_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="memory_poisoning_guard",
                        violation_code=mem_res.violation_code,
                        details=mem_res.details,
                        metadata={"message_index": msg_idx, "poison_type": mem_res.poison_type}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": mem_res.violation_code,
                                "message": f"Inbound prompt blocked by Memory Poisoning Guard: {mem_res.details}",
                                "guard": "memory_poisoning_guard",
                            }
                        },
                        context=context
                    )

            # 1i. Insecure Deserialization & Polyglot Payload Guard
            if self.settings.ENABLE_DESERIALIZATION_GUARD and text_to_check:
                deser_res = self.deserialization_guard.inspect_text(text_to_check)
                if deser_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="deserialization_guard",
                        violation_code=deser_res.violation_code,
                        details=deser_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": deser_res.violation_code,
                                "message": f"Inbound prompt blocked by Deserialization Guard: {deser_res.details}",
                                "guard": "deserialization_guard",
                            }
                        },
                        context=context
                    )

            # 1j. Context Bomb & Recursive Expansion DoS Guard
            if self.settings.ENABLE_CONTEXT_BOMB_GUARD and text_to_check:
                bomb_res = self.context_bomb_guard.inspect_text(text_to_check)
                if bomb_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="context_bomb_guard",
                        violation_code=bomb_res.violation_code,
                        details=bomb_res.details,
                        metadata={"message_index": msg_idx, "bomb_type": bomb_res.bomb_type}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": bomb_res.violation_code,
                                "message": f"Inbound prompt blocked by Context Bomb Guard: {bomb_res.details}",
                                "guard": "context_bomb_guard",
                            }
                        },
                        context=context
                    )

            # 1k. Agent Tool RBAC Simulated Text Attempt Check
            if self.settings.ENABLE_AGENT_TOOL_RBAC_GUARD and text_to_check:
                caller_role = payload.get("caller_role") or payload.get("role") or "agent_worker"
                text_tool_res = self.agent_tool_rbac_guard.inspect_text_tool_attempts(caller_role, text_to_check)
                if text_tool_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="agent_tool_rbac_guard",
                        violation_code=text_tool_res.violation_code or "unauthorized_text_tool_invocation",
                        details=text_tool_res.details,
                        metadata={"tool_name": text_tool_res.tool_name, "caller_role": caller_role}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": text_tool_res.violation_code or "unauthorized_text_tool_invocation",
                                "message": f"Inbound prompt blocked by Agent RBAC Guard: {text_tool_res.details}",
                                "guard": "agent_tool_rbac_guard",
                                "tool": text_tool_res.tool_name,
                            }
                        },
                        context=context
                    )

            # 1l. Epistemic Authority Hallucination & Ungrounded Waiver Guard
            if self.settings.ENABLE_EPISTEMIC_GUARD and text_to_check:
                ep_res = self.epistemic_guard.inspect_text(text_to_check)
                if ep_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="epistemic_uncertainty_guard",
                        violation_code=ep_res.violation_code or "fabricated_authority_blocked",
                        details=ep_res.details,
                        metadata={"message_index": msg_idx, "detected_claim": ep_res.detected_claim}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": ep_res.violation_code or "fabricated_authority_blocked",
                                "message": f"Inbound prompt blocked by Epistemic Authority Guard: {ep_res.details}",
                                "guard": "epistemic_uncertainty_guard",
                            }
                        },
                        context=context
                    )

            # 1m. Shadow In-Context Demonstration & Few-Shot Hijack Guard
            if self.settings.ENABLE_SHADOW_DEMO_GUARD and text_to_check:
                shadow_res = self.shadow_demo_guard.inspect(text_to_check)
                if shadow_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="shadow_demonstration_guard",
                        violation_code=shadow_res.violation_code or "shadow_demonstration_blocked",
                        details=shadow_res.details,
                        metadata={"message_index": msg_idx, "pattern_type": shadow_res.pattern_type}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": shadow_res.violation_code or "shadow_demonstration_blocked",
                                "message": f"Inbound prompt blocked by Shadow Demonstration Guard: {shadow_res.details}",
                                "guard": "shadow_demonstration_guard",
                            }
                        },
                        context=context
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

            # 2b. Agent Goal Drift & Roleplay Hijacking Guard
            if self.settings.ENABLE_GOAL_DRIFT_DETECTOR and text_to_check:
                drift_detected, drift_score, drift_reason = self.goal_drift_detector.inspect_prompt(text_to_check)
                if drift_detected:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="goal_drift_detector",
                        violation_code="goal_drift_detected",
                        details=drift_reason,
                        metadata={"risk_score": drift_score, "message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "goal_drift_detected",
                                "message": f"Inbound prompt blocked by Goal Drift Detector: {drift_reason}",
                                "guard": "goal_drift_detector",
                                "risk_score": drift_score,
                            }
                        },
                        context=context
                    )

            # 2c. Semantic Similarity Evasion & Paraphrased Jailbreak Guard
            if self.settings.ENABLE_SEMANTIC_SIMILARITY_GUARD and text_to_check:
                sim_res = self.semantic_similarity_guard.inspect_text(text_to_check)
                if sim_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="semantic_similarity_guard",
                        violation_code=sim_res.violation_code or "semantic_similarity_jailbreak_detected",
                        details=sim_res.details,
                        metadata={"similarity_score": sim_res.similarity_score, "matched_intent": sim_res.matched_intent, "message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": sim_res.violation_code or "semantic_similarity_jailbreak_detected",
                                "message": f"Inbound prompt blocked by Semantic Similarity Guard: {sim_res.details}",
                                "guard": "semantic_similarity_guard",
                                "similarity_score": sim_res.similarity_score,
                            }
                        },
                        context=context
                    )

            # 2d. Indirect RAG Document Poison & Canary Extraction Guard
            if self.settings.ENABLE_RAG_POISON_GUARD and text_to_check:
                rag_res = self.rag_poison_guard.inspect_text(text_to_check)
                if rag_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="rag_poison_guard",
                        violation_code=rag_res.violation_code or "indirect_rag_poison_detected",
                        details=rag_res.details,
                        metadata={"poison_type": rag_res.poison_type, "message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": rag_res.violation_code or "indirect_rag_poison_detected",
                                "message": f"Inbound prompt blocked by RAG Poison Guard: {rag_res.details}",
                                "guard": "rag_poison_guard",
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

            # 3d. Steganographic Separator & Covert Exfiltration Guard
            if self.settings.ENABLE_STEGO_SEPARATOR_GUARD and text_to_check:
                stego_res = self.stego_separator_guard.inspect_text(text_to_check)
                if stego_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="stego_separator_guard",
                        violation_code=stego_res.violation_code or "steganographic_separator_detected",
                        details=stego_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": stego_res.violation_code or "steganographic_separator_detected",
                                "message": f"Inbound prompt blocked by Stego Separator Guard: {stego_res.details}",
                                "guard": "stego_separator_guard",
                            }
                        },
                        context=context
                    )

            # 3e. Adaptive Prompt Mutation & Fuzzing Evasion Guard
            if self.settings.ENABLE_MUTATION_FUZZ_GUARD and text_to_check:
                mut_res = self.mutation_fuzz_guard.inspect_text(text_to_check)
                if mut_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="mutation_fuzz_guard",
                        violation_code=mut_res.violation_code or "prompt_mutation_fuzz_detected",
                        details=mut_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": mut_res.violation_code or "prompt_mutation_fuzz_detected",
                                "message": f"Inbound prompt blocked by Mutation Fuzz Guard: {mut_res.details}",
                                "guard": "mutation_fuzz_guard",
                            }
                        },
                        context=context
                    )

            # 3f. Obfuscation & Zero-Width Evasion Guard
            if self.settings.ENABLE_OBFUSCATION_EVASION_GUARD and text_to_check:
                obf_res = self.obfuscation_evasion_guard.inspect_text(text_to_check)
                if obf_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="obfuscation_evasion_guard",
                        violation_code=obf_res.violation_code or "zero_width_evasion_detected",
                        details=obf_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": obf_res.violation_code or "zero_width_evasion_detected",
                                "message": f"Inbound prompt blocked by Obfuscation Evasion Guard: {obf_res.details}",
                                "guard": "obfuscation_evasion_guard",
                            }
                        },
                        context=context
                    )
                text_to_check = obf_res.cleaned_text

            # 3g. Token Frequency Entropy Guard
            if self.settings.ENABLE_TOKEN_ENTROPY_GUARD and text_to_check:
                ent_res = self.token_entropy_guard.inspect_text(text_to_check)
                if ent_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="token_entropy_guard",
                        violation_code=ent_res.violation_code or "low_entropy_token_stuffing",
                        details=ent_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": ent_res.violation_code or "low_entropy_token_stuffing",
                                "message": f"Inbound prompt blocked by Token Entropy Guard: {ent_res.details}",
                                "guard": "token_entropy_guard",
                            }
                        },
                        context=context
                    )

            # 3h. Feedback Loop Dampening Guard
            if self.settings.ENABLE_FEEDBACK_LOOP_GUARD and text_to_check and ("session_id" in payload or "agent_id" in payload):
                sess_id = payload.get("session_id") or client_ip or "default_session"
                snd_id = payload.get("agent_id") or "agent_turn"
                fb_res = self.feedback_loop_guard.inspect_turn(sess_id, snd_id, text_to_check)
                if fb_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="feedback_loop_guard",
                        violation_code=fb_res.violation_code or "agent_feedback_resonance_loop",
                        details=fb_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": fb_res.violation_code or "agent_feedback_resonance_loop",
                                "message": f"Inbound prompt blocked by Feedback Loop Guard: {fb_res.details}",
                                "guard": "feedback_loop_guard",
                            }
                        },
                        context=context
                    )

            # 3i. Cross-Context Contamination Guard
            if self.settings.ENABLE_CROSS_CONTEXT_GUARD and text_to_check:
                sess_id = payload.get("session_id") or context.request_id
                cc_res = self.cross_context_guard.inspect_text_for_contamination(sess_id, text_to_check)
                if cc_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="cross_context_guard",
                        violation_code=cc_res.violation_code or "cross_session_context_bleeding",
                        details=cc_res.details,
                        metadata={"session_id": sess_id}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": cc_res.violation_code or "cross_session_context_bleeding",
                                "message": f"Inbound prompt blocked by Cross-Context Guard: {cc_res.details}",
                                "guard": "cross_context_guard",
                            }
                        },
                        context=context
                    )

            # 3j. Model Inversion Defense Guard
            if self.settings.ENABLE_MODEL_INVERSION_GUARD and text_to_check:
                inv_res = self.model_inversion_guard.inspect_prompt(text_to_check)
                if inv_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="model_inversion_guard",
                        violation_code=inv_res.violation_code or "model_inversion_probe",
                        details=inv_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": inv_res.violation_code or "model_inversion_probe",
                                "message": f"Inbound prompt blocked by Model Inversion Guard: {inv_res.details}",
                                "guard": "model_inversion_guard",
                            }
                        },
                        context=context
                    )

            # 3k. Semantic Boundary Guard
            if self.settings.ENABLE_SEMANTIC_BOUNDARY_GUARD and text_to_check:
                sb_res = self.semantic_boundary_guard.seal_untrusted_content("inbound_prompt", text_to_check, strict_block_on_escape=True)
                if sb_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="semantic_boundary_guard",
                        violation_code=sb_res.violation_code or "semantic_boundary_escape",
                        details=sb_res.details,
                        metadata={"message_index": msg_idx}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": sb_res.violation_code or "semantic_boundary_escape",
                                "message": f"Inbound prompt blocked by Semantic Boundary Guard: {sb_res.details}",
                                "guard": "semantic_boundary_guard",
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
        inbound_tool_calls = payload.get("tool_calls") or payload.get("tools")
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

        # 4b. Inbound Tool Call SQL / NoSQL Injection Check
        if self.settings.ENABLE_SQL_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_args = fn.get("arguments", "")
                if isinstance(t_args, dict):
                    import json
                    t_args = json.dumps(t_args)
                sql_res = self.sql_guard.inspect(str(t_args))
                if sql_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="sql_nosql_guard",
                        violation_code=sql_res.violation_code,
                        details=sql_res.details,
                        metadata={"tool_name": fn.get("name", "")}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": sql_res.violation_code,
                                "message": f"Inbound tool call blocked by SQL/NoSQL Guard: {sql_res.details}",
                                "guard": "sql_nosql_guard",
                                "tool": fn.get("name", ""),
                            }
                        },
                        context=context
                    )

        # 4c. Inbound Tool Call Code Sandbox Policy Check
        if self.settings.ENABLE_AST_SANDBOX_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
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
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="code_sandbox_policy",
                            violation_code=ast_res.violation_code,
                            details=ast_res.details,
                            metadata={"tool_name": fn.get("name", "")}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": ast_res.violation_code,
                                    "message": f"Inbound tool call blocked by Code Sandbox Policy: {ast_res.details}",
                                    "guard": "code_sandbox_policy",
                                    "tool": fn.get("name", ""),
                                }
                            },
                            context=context
                        )

        # 4d. Command Injection & Chaining Check on Inbound Tool Calls
        if self.settings.ENABLE_COMMAND_INJECTION_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", "")
                cmd_res = self.command_injection_guard.inspect_arguments(t_args)
                if cmd_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="command_injection_guard",
                        violation_code=cmd_res.violation_code,
                        details=cmd_res.details,
                        metadata={"tool_name": t_name}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": cmd_res.violation_code or "command_injection_detected",
                                "message": f"Inbound tool call blocked by Command Injection Guard: {cmd_res.details}",
                                "guard": "command_injection_guard",
                                "tool": t_name,
                            }
                        },
                        context=context
                    )
        # 4e. Tool Parameter Type & Semantic Bounds Enforcer
        if self.settings.ENABLE_TOOL_PARAM_ENFORCER and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", "")
                param_res = self.tool_param_enforcer.validate_tool_call(t_name, t_args)
                if param_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="tool_param_enforcer",
                        violation_code=param_res.violation_code,
                        details=param_res.details,
                        metadata={"tool_name": t_name, "parameter": param_res.parameter_name}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": param_res.violation_code or "parameter_validation_failed",
                                "message": f"Inbound tool call blocked by Parameter Enforcer: {param_res.details}",
                                "guard": "tool_param_enforcer",
                                "tool": t_name,
                            }
                        },
                        context=context
                    )

        # 4f. Agent Tool Role-Based Access Control (RBAC) & Scope Guard
        if self.settings.ENABLE_AGENT_TOOL_RBAC_GUARD and inbound_tool_calls:
            caller_role = payload.get("caller_role") or payload.get("role") or "agent_worker"
            rbac_res = self.agent_tool_rbac_guard.validate_tool_calls(caller_role, inbound_tool_calls)
            if rbac_res.is_blocked:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=request_id,
                    client_ip=client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="agent_tool_rbac_guard",
                    violation_code=rbac_res.violation_code or "privilege_escalation_blocked",
                    details=rbac_res.details,
                    metadata={"tool_name": rbac_res.tool_name, "caller_role": caller_role}
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": rbac_res.violation_code or "privilege_escalation_blocked",
                            "message": f"Inbound tool call blocked by Agent RBAC Guard: {rbac_res.details}",
                            "guard": "agent_tool_rbac_guard",
                            "tool": rbac_res.tool_name,
                            "role": caller_role,
                        }
                    },
                    context=context
                )

        # 4g. Agent Tool Invocation Velocity & Burst Anomaly Guard
        if self.settings.ENABLE_AGENT_VELOCITY_GUARD and inbound_tool_calls:
            agent_id = payload.get("agent_id") or client_ip or "default_agent"
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                vel_res = self.agent_velocity_guard.record_and_check(agent_id, t_name)
                if vel_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="agent_velocity_guard",
                        violation_code=vel_res.violation_code or "agent_velocity_anomaly",
                        details=vel_res.details,
                        metadata={"tool_name": t_name, "agent_id": agent_id}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": vel_res.violation_code or "agent_velocity_anomaly",
                                "message": f"Inbound tool call blocked by Velocity Guard: {vel_res.details}",
                                "guard": "agent_velocity_guard",
                                "tool": t_name,
                                "agent_id": agent_id,
                            }
                        },
                        context=context
                    )

        # 4h. Session Anti-Replay Nonce & Timestamp Guard
        if self.settings.ENABLE_SESSION_REPLAY_GUARD:
            session_id = payload.get("session_id") or client_ip
            nonce = payload.get("nonce") or payload.get("idempotency_key")
            ts = payload.get("timestamp")
            if nonce:
                replay_res = self.session_replay_guard.validate_request(
                    session_id=session_id,
                    nonce=str(nonce),
                    timestamp=float(ts) if ts is not None else None
                )
                if replay_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="session_replay_guard",
                        violation_code=replay_res.violation_code or "replayed_authorization_detected",
                        details=replay_res.details,
                        metadata={"nonce": replay_res.nonce, "session_id": session_id}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": replay_res.violation_code or "replayed_authorization_detected",
                                "message": f"Inbound request blocked by Session Anti-Replay Guard: {replay_res.details}",
                                "guard": "session_replay_guard",
                            }
                        },
                        context=context
                    )
            if inbound_tool_calls:
                for tc in inbound_tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    t_args = fn.get("arguments", {})
                    if isinstance(t_args, str):
                        try:
                            import json
                            t_args = json.loads(t_args)
                        except Exception:
                            t_args = {}
                    if isinstance(t_args, dict):
                        tc_replay = self.session_replay_guard.validate_tool_call(
                            session_id=session_id,
                            tool_name=t_name,
                            parameters=t_args
                        )
                        if tc_replay.is_blocked:
                            latency = (time.time() - start_time) * 1000
                            audit_logger.log_event(
                                request_id=request_id,
                                client_ip=client_ip,
                                direction="inbound",
                                status="BLOCKED",
                                latency_ms=latency,
                                guard="session_replay_guard",
                                violation_code=tc_replay.violation_code or "replayed_authorization_detected",
                                details=tc_replay.details,
                                metadata={"nonce": tc_replay.nonce, "session_id": session_id, "tool_name": t_name}
                            )
                            return InboundPipelineResult(
                                is_allowed=False,
                                error_response={
                                    "error": {
                                        "type": "security_policy_violation",
                                        "code": tc_replay.violation_code or "replayed_authorization_detected",
                                        "message": f"Inbound tool call blocked by Session Anti-Replay Guard: {tc_replay.details}",
                                        "guard": "session_replay_guard",
                                        "tool": t_name,
                                    }
                                },
                                context=context
                            )

        # 4i. Agent Egress Domain Allowlist & SSRF Perimeter Guard
        if self.settings.ENABLE_EGRESS_ALLOWLIST_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", {})
                if isinstance(t_args, str):
                    try:
                        import json
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {}
                if isinstance(t_args, dict):
                    egress_res = self.egress_allowlist_guard.inspect_tool_call(t_name, t_args)
                    if egress_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="egress_domain_allowlist_guard",
                            violation_code=egress_res.violation_code or "unauthorized_egress_domain",
                            details=egress_res.details,
                            metadata={"tool_name": t_name, "target_host": egress_res.target_host}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": egress_res.violation_code or "unauthorized_egress_domain",
                                    "message": f"Inbound tool call blocked by Egress Allowlist Guard: {egress_res.details}",
                                    "guard": "egress_domain_allowlist_guard",
                                    "tool": t_name,
                                    "target_host": egress_res.target_host,
                                }
                            },
                            context=context
                        )

        # 4j. Catastrophic Parameter ReDoS & Complexity Guard
        if self.settings.ENABLE_PARAM_REDOS_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", {})
                if isinstance(t_args, str):
                    try:
                        import json
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {}
                if isinstance(t_args, dict):
                    redos_res = self.param_redos_guard.inspect_tool_call(t_name, t_args)
                    if redos_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="param_redos_guard",
                            violation_code=redos_res.violation_code or "catastrophic_redos_signature",
                            details=redos_res.details,
                            metadata={"tool_name": t_name, "vulnerability_type": redos_res.vulnerability_type}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": redos_res.violation_code or "catastrophic_redos_signature",
                                    "message": f"Inbound tool call blocked by Parameter ReDoS Guard: {redos_res.details}",
                                    "guard": "param_redos_guard",
                                    "tool": t_name,
                                }
                            },
                            context=context
                        )

        # 4k. Decompression Bomb & Zip-Slip Guard
        if self.settings.ENABLE_DECOMPRESSION_BOMB_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", {})
                if isinstance(t_args, str):
                    try:
                        import json
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {}
                if isinstance(t_args, dict):
                    decomp_res = self.decompression_bomb_guard.inspect_tool_call(t_name, t_args)
                    if decomp_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="decompression_bomb_guard",
                            violation_code=decomp_res.violation_code or "decompression_bomb_detected",
                            details=decomp_res.details,
                            metadata={"tool_name": t_name, "compression_ratio": decomp_res.compression_ratio}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": decomp_res.violation_code or "decompression_bomb_detected",
                                    "message": f"Inbound tool call blocked by Decompression Bomb Guard: {decomp_res.details}",
                                    "guard": "decompression_bomb_guard",
                                    "tool": t_name,
                                }
                            },
                            context=context
                        )

        # 4l. Parameter Semantic Differential Validator
        if self.settings.ENABLE_PARAM_DIFFERENTIAL_GUARD and inbound_tool_calls:
            user_prompt = ""
            for m in messages:
                if isinstance(m, dict) and m.get("role") == "user":
                    user_prompt = m.get("content", "")
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", {})
                if isinstance(t_args, str):
                    try:
                        import json
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {}
                if isinstance(t_args, dict):
                    diff_res = self.param_differential_guard.inspect_differential(user_prompt, t_name, t_args)
                    if diff_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="param_differential_guard",
                            violation_code=diff_res.violation_code or "unprompted_destructive_tool_invocation",
                            details=diff_res.details,
                            metadata={"tool_name": t_name, "divergence_score": diff_res.divergence_score}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": diff_res.violation_code or "unprompted_destructive_tool_invocation",
                                    "message": f"Inbound tool call blocked by Param Differential Guard: {diff_res.details}",
                                    "guard": "param_differential_guard",
                                    "tool": t_name,
                                }
                            },
                            context=context
                        )

        # 4m. Ephemeral Capability Token Scoping Guard
        if self.settings.ENABLE_CAPABILITY_TOKEN_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", {})
                if isinstance(t_args, str):
                    try:
                        import json
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {}
                if isinstance(t_args, dict):
                    cap_res = self.capability_token_guard.inspect_tool_call(t_name, t_args)
                    if cap_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="capability_token_guard",
                            violation_code=cap_res.violation_code or "missing_capability_token",
                            details=cap_res.details,
                            metadata={"tool_name": t_name}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": cap_res.violation_code or "missing_capability_token",
                                    "message": f"Inbound tool call blocked by Capability Token Guard: {cap_res.details}",
                                    "guard": "capability_token_guard",
                                    "tool": t_name,
                                }
                            },
                            context=context
                        )

        # 4n. Inbound Tool Call Schema Mutation & Prototype Hijack Guard
        if self.settings.ENABLE_SCHEMA_MUTATION_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", {})
                if isinstance(t_args, str):
                    try:
                        import json
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {}
                if isinstance(t_args, dict):
                    sm_ok, sm_err = self.schema_mutation_guard.validate_tool_arguments(t_name, t_args)
                    if not sm_ok:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="schema_mutation_guard",
                            violation_code="schema_mutation_prototype_hijack",
                            details=sm_err,
                            metadata={"tool_name": t_name}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": "schema_mutation_prototype_hijack",
                                    "message": f"Inbound tool call blocked by Schema Mutation Guard: {sm_err}",
                                    "guard": "schema_mutation_guard",
                                    "tool": t_name,
                                }
                            },
                            context=context
                        )

        # 4o. Inbound Tool Call Argument Sanitizer Guard
        if self.settings.ENABLE_ARGUMENT_SANITIZER_GUARD and inbound_tool_calls:
            for tc in inbound_tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                t_name = fn.get("name", "")
                t_args = fn.get("arguments", {})
                arg_res = self.argument_sanitizer_guard.sanitize_arguments(t_name, t_args)
                if arg_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=request_id,
                        client_ip=client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="argument_sanitizer_guard",
                        violation_code=arg_res.violation_code or "argument_sanitizer_violation",
                        details=arg_res.details,
                        metadata={"tool_name": t_name}
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": arg_res.violation_code or "argument_sanitizer_violation",
                                "message": f"Inbound tool call blocked by Argument Sanitizer Guard: {arg_res.details}",
                                "guard": "argument_sanitizer_guard",
                                "tool": t_name,
                            }
                        },
                        context=context
                    )
                elif arg_res.sanitized_args is not None and isinstance(t_args, dict):
                    fn["arguments"] = arg_res.sanitized_args


        # Agent Tool Concurrency & Deadlock Prevention Guard
        if self.settings.ENABLE_TOOL_CONCURRENCY_GUARD and inbound_tool_calls:
            sess_id = payload.get("session_id", context.request_id)
            for tc in inbound_tool_calls:
                if isinstance(tc, dict):
                    t_name = tc.get("function", {}).get("name", "unknown_tool")
                    t_id = tc.get("id", f"call_{request_id}")
                    req_res = tc.get("requested_resources", [])
                    conc_res = self.tool_concurrency_guard.acquire_execution_slot(
                        session_id=sess_id,
                        execution_id=t_id,
                        tool_name=t_name,
                        requested_resources=req_res if isinstance(req_res, list) else None,
                    )
                    if conc_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="tool_concurrency_guard",
                            violation_code=conc_res.violation_code,
                            details=conc_res.details,
                            metadata={"tool_name": t_name}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": conc_res.violation_code,
                                    "message": f"Inbound tool call blocked by Tool Concurrency Guard: {conc_res.details}",
                                    "guard": "tool_concurrency_guard",
                                    "tool": t_name,
                                }
                            },
                            context=context
                        )

        # Agent Action Idempotency & Duplicate Execution Guard
        if self.settings.ENABLE_ACTION_IDEMPOTENCY_GUARD and inbound_tool_calls:
            sess_id = payload.get("session_id", context.request_id)
            for tc in inbound_tool_calls:
                if isinstance(tc, dict):
                    t_name = tc.get("function", {}).get("name", "unknown_tool")
                    t_args = tc.get("function", {}).get("arguments", {})
                    if isinstance(t_args, str):
                        try:
                            t_args = json.loads(t_args)
                        except Exception:
                            t_args = {}
                    idem_key = tc.get("idempotency_key")
                    idem_res = self.action_idempotency_guard.validate_action(
                        session_id=sess_id,
                        tool_name=t_name,
                        arguments=t_args if isinstance(t_args, dict) else {},
                        explicit_idempotency_key=idem_key,
                    )
                    if idem_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=request_id,
                            client_ip=client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="action_idempotency_guard",
                            violation_code=idem_res.violation_code,
                            details=idem_res.details,
                            metadata={"tool_name": t_name}
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": idem_res.violation_code,
                                    "message": f"Inbound tool call blocked by Idempotency Guard: {idem_res.details}",
                                    "guard": "action_idempotency_guard",
                                    "tool": t_name,
                                }
                            },
                            context=context
                        )

        # Sidechannel Timing Attack Guard
        if self.settings.ENABLE_SIDECHANNEL_TIMING_GUARD:
            timing_res = self.sidechannel_timing_guard.evaluate_request_timing(
                session_id=payload.get("session_id", context.request_id)
            )
            if timing_res.is_blocked:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=context.request_id,
                    client_ip=context.client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="sidechannel_timing_guard",
                    violation_code=timing_res.violation_code,
                    details=timing_res.details
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": timing_res.violation_code,
                            "message": f"Inbound request blocked by Sidechannel Timing Guard: {timing_res.details}",
                            "guard": "sidechannel_timing_guard",
                        }
                    },
                    context=context
                )

        # Subagent Privilege Escalation Guard
        if self.settings.ENABLE_SUBAGENT_PRIVILEGE_ESCALATION_GUARD and inbound_tool_calls:
            sub_id = payload.get("subagent_id")
            if sub_id:
                for tc in inbound_tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    priv_res = self.subagent_privilege_guard.evaluate_subagent_action(sub_id, t_name)
                    if priv_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=context.request_id,
                            client_ip=context.client_ip,
                            direction="inbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="subagent_privilege_escalation_guard",
                            violation_code=priv_res.violation_code,
                            details=priv_res.details
                        )
                        return InboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": priv_res.violation_code,
                                    "message": f"Inbound request blocked by Privilege Escalation Guard: {priv_res.details}",
                                    "guard": "subagent_privilege_escalation_guard",
                                }
                            },
                            context=context
                        )

        # Multi-Tenant Sandbox Jail Guard
        if self.settings.ENABLE_MULTI_TENANT_SANDBOX_JAIL_GUARD:
            tenant_id = payload.get("tenant_id")
            target_path = payload.get("sandbox_path") or payload.get("file_path")
            if tenant_id and target_path:
                jail_res = self.sandbox_jail_guard.validate_tenant_path(tenant_id, target_path)
                if jail_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="multi_tenant_sandbox_jail_guard",
                        violation_code=jail_res.violation_code,
                        details=jail_res.details
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": jail_res.violation_code,
                                "message": f"Inbound request blocked by Sandbox Jail Guard: {jail_res.details}",
                                "guard": "multi_tenant_sandbox_jail_guard",
                            }
                        },
                        context=context
                    )

        # Adaptive Risk-Weighted Rate & Burst Throttling Guard
        if self.settings.ENABLE_ADAPTIVE_RATE_BURST_GUARD:
            sess_id = payload.get("session_id", context.request_id)
            risk_lvl = float(payload.get("risk_score", 0.0))
            token_cst = float(payload.get("token_cost", 1.0))
            burst_res = self.adaptive_rate_burst_guard.evaluate_request(
                session_id=sess_id,
                token_cost=token_cst,
                risk_score=risk_lvl,
            )
            if burst_res.is_blocked:
                latency = (time.time() - start_time) * 1000
                audit_logger.log_event(
                    request_id=context.request_id,
                    client_ip=context.client_ip,
                    direction="inbound",
                    status="BLOCKED",
                    latency_ms=latency,
                    guard="adaptive_rate_burst_guard",
                    violation_code=burst_res.violation_code,
                    details=burst_res.details
                )
                return InboundPipelineResult(
                    is_allowed=False,
                    error_response={
                        "error": {
                            "type": "security_policy_violation",
                            "code": burst_res.violation_code,
                            "message": f"Inbound request throttled by Adaptive Burst Guard: {burst_res.details}",
                            "guard": "adaptive_rate_burst_guard",
                        }
                    },
                    context=context
                )

        # Semantic Cache Poisoning Defense Guard
        if self.settings.ENABLE_SEMANTIC_CACHE_POISONING_GUARD and "cache_key" in payload:
            ck = payload.get("cache_key", "")
            cp_prompt = payload.get("cache_prompt", "")
            cp_resp = payload.get("cache_response", "")
            user_p = ""
            for m in payload.get("messages", []):
                if isinstance(m, dict) and m.get("role") == "user":
                    user_p = m.get("content", "")
            if user_p and cp_prompt and user_p != cp_prompt:
                self.cache_poisoning_guard.evaluate_cache_write(ck, user_p, "clean_seed")
            if ck and cp_prompt:
                cp_res = self.cache_poisoning_guard.evaluate_cache_write(ck, cp_prompt, cp_resp)
                if cp_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="inbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="semantic_cache_poisoning_guard",
                        violation_code=cp_res.violation_code,
                        details=cp_res.details
                    )
                    return InboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": cp_res.violation_code,
                                "message": f"Inbound cache write blocked by Cache Poisoning Guard: {cp_res.details}",
                                "guard": "semantic_cache_poisoning_guard",
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

            # -0.8. Structured Output Schema Validator Guard
            if self.settings.ENABLE_SCHEMA_VALIDATOR_GUARD and content and "expected_schema" in response_json:
                schema_res = self.schema_validator_guard.validate_json_response(content, response_json["expected_schema"])
                if not schema_res.is_valid:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="schema_validator_guard",
                        violation_code=schema_res.violation_code or "schema_validation_failed",
                        details=schema_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "schema_validation_error",
                                "code": schema_res.violation_code or "schema_validation_failed",
                                "message": f"Outbound response violated schema: {schema_res.details}",
                                "guard": "schema_validator_guard",
                            }
                        }
                    )

            # -0.5. Agent Tool Egress Payload Sanitizer Guard
            if self.settings.ENABLE_EGRESS_PAYLOAD_SANITIZER_GUARD and tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    t_args = fn.get("arguments", "")
                    raw_str = t_args if isinstance(t_args, str) else json.dumps(t_args)
                    eg_res = self.egress_sanitizer_guard.inspect_payload(t_name, raw_str)
                    if eg_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=context.request_id,
                            client_ip=context.client_ip,
                            direction="outbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="egress_payload_sanitizer_guard",
                            violation_code=eg_res.violation_code or "egress_data_leak",
                            details=eg_res.details,
                            metadata={"tool_name": t_name}
                        )
                        return OutboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": eg_res.violation_code or "egress_data_leak",
                                    "message": f"Outbound tool call blocked by Egress Sanitizer Guard: {eg_res.details}",
                                    "guard": "egress_payload_sanitizer_guard",
                                    "tool": t_name,
                                }
                            }
                        )

            # 0. Agent Tool Recursion Depth & Budget Quota Check
            if self.settings.ENABLE_RECURSION_BUDGET_GUARD and tool_calls:
                budget_res = self.recursion_budget_guard.check_tool_calls(context.request_id, tool_calls)
                if budget_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="recursion_budget_guard",
                        violation_code=budget_res.violation_code,
                        details=budget_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": budget_res.violation_code or "recursion_limit_exceeded",
                                "message": f"Agentic tool call blocked by Recursion Budget Guard: {budget_res.details}",
                                "guard": "recursion_budget_guard",
                            }
                        }
                    )

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

            # 1e. Command Injection & Parameter Chaining Check
            if self.settings.ENABLE_COMMAND_INJECTION_GUARD and tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    t_args = fn.get("arguments", "")
                    cmd_res = self.command_injection_guard.inspect_arguments(t_args)
                    if cmd_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=context.request_id,
                            client_ip=context.client_ip,
                            direction="outbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="command_injection_guard",
                            violation_code=cmd_res.violation_code,
                            details=cmd_res.details,
                            metadata={"tool_name": t_name}
                        )
                        return OutboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": cmd_res.violation_code or "command_injection_detected",
                                     "message": f"Agentic tool call blocked by Command Injection Guard: {cmd_res.details}",
                                    "guard": "command_injection_guard",
                                    "tool": t_name,
                                }
                            }
                        )

            # 1f. Outbound Agent Egress Domain Allowlist Check
            if self.settings.ENABLE_EGRESS_ALLOWLIST_GUARD and tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    t_args = fn.get("arguments", {})
                    if isinstance(t_args, str):
                        try:
                            t_args = json.loads(t_args)
                        except Exception:
                            t_args = {}
                    if isinstance(t_args, dict):
                        egress_res = self.egress_allowlist_guard.inspect_tool_call(t_name, t_args)
                        if egress_res.is_blocked:
                            latency = (time.time() - start_time) * 1000
                            audit_logger.log_event(
                                request_id=context.request_id,
                                client_ip=context.client_ip,
                                direction="outbound",
                                status="BLOCKED",
                                latency_ms=latency,
                                guard="egress_domain_allowlist_guard",
                                violation_code=egress_res.violation_code or "unauthorized_egress_domain",
                                details=egress_res.details,
                                metadata={"tool_name": t_name, "target_host": egress_res.target_host}
                            )
                            return OutboundPipelineResult(
                                is_allowed=False,
                                error_response={
                                    "error": {
                                        "type": "security_policy_violation",
                                        "code": egress_res.violation_code or "unauthorized_egress_domain",
                                        "message": f"Outbound tool call blocked by Egress Allowlist Guard: {egress_res.details}",
                                        "guard": "egress_domain_allowlist_guard",
                                        "tool": t_name,
                                    }
                                }
                            )

            # 1g. Outbound Parameter ReDoS Complexity Check
            if self.settings.ENABLE_PARAM_REDOS_GUARD and tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    t_name = fn.get("name", "")
                    t_args = fn.get("arguments", {})
                    if isinstance(t_args, str):
                        try:
                            t_args = json.loads(t_args)
                        except Exception:
                            t_args = {}
                    if isinstance(t_args, dict):
                        redos_res = self.param_redos_guard.inspect_tool_call(t_name, t_args)
                        if redos_res.is_blocked:
                            latency = (time.time() - start_time) * 1000
                            audit_logger.log_event(
                                request_id=context.request_id,
                                client_ip=context.client_ip,
                                direction="outbound",
                                status="BLOCKED",
                                latency_ms=latency,
                                guard="param_redos_guard",
                                violation_code=redos_res.violation_code or "catastrophic_redos_signature",
                                details=redos_res.details,
                                metadata={"tool_name": t_name}
                            )
                            return OutboundPipelineResult(
                                is_allowed=False,
                                error_response={
                                    "error": {
                                        "type": "security_policy_violation",
                                        "code": redos_res.violation_code or "catastrophic_redos_signature",
                                        "message": f"Outbound tool call blocked by Parameter ReDoS Guard: {redos_res.details}",
                                        "guard": "param_redos_guard",
                                        "tool": t_name,
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

                # 2c. Fuzzy Canary Reflection Attenuation Guard
                if self.settings.ENABLE_CANARY_ATTENUATION_GUARD:
                    atten_res = self.canary_attenuation_guard.inspect_text(content)
                    if atten_res.is_blocked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=context.request_id,
                            client_ip=context.client_ip,
                            direction="outbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="canary_reflection_attenuation_guard",
                            violation_code=atten_res.violation_code or "canary_reflection_detected",
                            details=atten_res.details,
                            metadata={"similarity_score": atten_res.similarity_score}
                        )
                        return OutboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": atten_res.violation_code or "canary_reflection_detected",
                                    "message": f"Outbound completion blocked by Canary Reflection Attenuation Guard: {atten_res.details}",
                                    "guard": "canary_reflection_attenuation_guard",
                                }
                            }
                        )
                    if atten_res.is_attenuated and atten_res.attenuated_text:
                        content = atten_res.attenuated_text
                        msg["content"] = content

                # 2d. Dynamic Canary Watermark Rotation & Egress Leak Guard
                if self.settings.ENABLE_CANARY_ROTATION_GUARD and content:
                    rot_res = self.canary_rotation_guard.scan_for_leak(content)
                    if rot_res.is_leaked:
                        latency = (time.time() - start_time) * 1000
                        audit_logger.log_event(
                            request_id=context.request_id,
                            client_ip=context.client_ip,
                            direction="outbound",
                            status="BLOCKED",
                            latency_ms=latency,
                            guard="canary_rotation_guard",
                            violation_code=rot_res.violation_code or "system_prompt_canary_leak_detected",
                            details=rot_res.details
                        )
                        return OutboundPipelineResult(
                            is_allowed=False,
                            error_response={
                                "error": {
                                    "type": "security_policy_violation",
                                    "code": rot_res.violation_code or "system_prompt_canary_leak_detected",
                                    "message": f"Outbound completion blocked by Canary Rotation Guard: {rot_res.details}",
                                    "guard": "canary_rotation_guard",
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

            # 3e. Goal Drift & Persona Hijack Check
            if self.settings.ENABLE_GOAL_DRIFT_DETECTOR and content:
                drifted, d_score, d_reason = self.goal_drift_detector.inspect_completion(content)
                if drifted:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="goal_drift_detector",
                        violation_code="goal_hijack_detected",
                        details=d_reason
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "goal_hijack_detected",
                                "message": f"Outbound completion blocked by Goal Drift Guard: {d_reason}",
                                "guard": "goal_drift_detector",
                            }
                        }
                    )

            # 3f. Outbound JSON Schema and Script Enforcer
            if self.settings.ENABLE_STRUCTURED_OUTPUT_ENFORCER and content and content.strip().startswith(("{", "[")):
                valid_json, json_err, _ = self.json_schema_enforcer.validate_json_string(content)
                if not valid_json and "JSON syntax error" not in (json_err or ""):
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="json_schema_enforcer",
                        violation_code="structured_output_violation",
                        details=json_err
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": "structured_output_violation",
                                "message": f"Outbound completion blocked by Structured Output Enforcer: {json_err}",
                                "guard": "json_schema_enforcer",
                            }
                        }
                    )

            # 3g. Active Canary Redaction & System Leak Scrubber
            if self.settings.ENABLE_CANARY_SCRUBBER and content:
                content, _, _ = self.canary_scrubber.scrub(content)

            # 3h. Outbound Context Exfiltration Link Inspection
            if self.settings.ENABLE_CONTEXT_EXFILTRATION_GUARD and content:
                exfil_res = self.context_exfil_guard.inspect_text(content)
                if exfil_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="context_exfiltration_guard",
                        violation_code=exfil_res.violation_code,
                        details=exfil_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": exfil_res.violation_code,
                                "message": f"Outbound completion blocked by Context Exfiltration Guard: {exfil_res.details}",
                                "guard": "context_exfiltration_guard",
                            }
                        }
                    )

            # 3i. Semantic Loop and Agent Deadlock Breaker
            if self.settings.ENABLE_SEMANTIC_LOOP_BREAKER and content:
                loop_res = self.semantic_loop_breaker.check_turn(context.request_id, content)
                if loop_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="semantic_loop_breaker",
                        violation_code=loop_res.violation_code,
                        details=loop_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": loop_res.violation_code,
                                "message": f"Outbound completion blocked by Semantic Loop Breaker: {loop_res.details}",
                                "guard": "semantic_loop_breaker",
                            }
                        }
                    )

            # 3j. Agent Reflection Loop & Paralysis Guard
            if self.settings.ENABLE_AGENT_REFLECTION_LOOP_GUARD and content:
                refl_res = self.reflection_loop_guard.evaluate_step(context.request_id, content)
                if refl_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="agent_reflection_loop_guard",
                        violation_code=refl_res.violation_code,
                        details=refl_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": refl_res.violation_code,
                                "message": f"Outbound completion blocked by Reflection Loop Guard: {refl_res.details}",
                                "guard": "agent_reflection_loop_guard",
                            }
                        }
                    )

            # 3k. Cross-Tenant Token Bleed & Memory Residue Guard
            if self.settings.ENABLE_CROSS_TENANT_TOKEN_BLEED_GUARD and content:
                curr_tenant = response_json.get("tenant_id") or "tenant_default"
                bleed_res = self.token_bleed_guard.scan_response_for_bleed(curr_tenant, content)
                if bleed_res.is_blocked:
                    latency = (time.time() - start_time) * 1000
                    audit_logger.log_event(
                        request_id=context.request_id,
                        client_ip=context.client_ip,
                        direction="outbound",
                        status="BLOCKED",
                        latency_ms=latency,
                        guard="cross_tenant_token_bleed_guard",
                        violation_code=bleed_res.violation_code,
                        details=bleed_res.details
                    )
                    return OutboundPipelineResult(
                        is_allowed=False,
                        error_response={
                            "error": {
                                "type": "security_policy_violation",
                                "code": bleed_res.violation_code,
                                "message": f"Outbound completion blocked by Token Bleed Guard: {bleed_res.details}",
                                "guard": "cross_tenant_token_bleed_guard",
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
