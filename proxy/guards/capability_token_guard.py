"""
Ephemeral Capability-Token Scoping and Delegation Guard for Agent Tools.

Mitigates OWASP LLM08 (Excessive Agency) and Confused Deputy attacks by issuing
and verifying HMAC-signed, time-bounded, resource-scoped capability tokens required
for agent tool execution.
"""

import hmac
import hashlib
import json
import base64
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set


@dataclass
class CapabilityTokenResult:
    is_valid: bool
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed capability token validation"
    agent_id: Optional[str] = None
    granted_scopes: List[str] = field(default_factory=list)


class CapabilityTokenGuard:
    """
    Validates cryptographically signed ephemeral capability tokens passed in tool calls.
    """

    CAPABILITY_KEYS = {"capability_token", "cap_token", "auth_token", "delegation_token"}

    def __init__(
        self,
        secret_key: str = "proxy-capability-token-secret-key-2026",
        default_ttl_seconds: float = 120.0,
        enforce_capability_tokens: bool = True
    ):
        self.secret_key = secret_key.encode("utf-8")
        self.default_ttl_seconds = default_ttl_seconds
        self.enforce_capability_tokens = enforce_capability_tokens
        self._consumed_nonces: Dict[str, float] = {}

    def issue_token(
        self,
        agent_id: str,
        tool_name: str,
        scopes: List[str],
        ttl_seconds: Optional[float] = None
    ) -> str:
        """Issues a signed, base64-encoded capability token."""
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        exp = now + ttl
        nonce = f"{agent_id}:{now}:{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:12]}"

        payload = {
            "sub": agent_id,
            "tool": tool_name,
            "scopes": scopes,
            "exp": exp,
            "nonce": nonce
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()

        token_obj = {
            "payload": base64.urlsafe_b64encode(payload_bytes).decode("ascii"),
            "sig": signature
        }
        return base64.urlsafe_b64encode(json.dumps(token_obj).encode("utf-8")).decode("ascii")

    def _purge_nonces(self, current_time: float):
        cutoff = current_time - 3600.0
        expired = [n for n, ts in self._consumed_nonces.items() if ts < cutoff]
        for n in expired:
            del self._consumed_nonces[n]

    def verify_token(
        self,
        token_str: str,
        expected_tool: str,
        required_scope: Optional[str] = None,
        now: Optional[float] = None
    ) -> CapabilityTokenResult:
        """Verifies signature, expiration, tool binding, nonce uniqueness, and scope."""
        current_time = now if now is not None else time.time()
        self._purge_nonces(current_time)

        if not token_str:
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=self.enforce_capability_tokens,
                violation_code="missing_capability_token",
                details="Tool execution lacks required ephemeral capability token."
            )

        try:
            raw_json = base64.urlsafe_b64decode(token_str.encode("ascii")).decode("utf-8")
            token_obj = json.loads(raw_json)
            payload_b64 = token_obj["payload"]
            sig = token_obj["sig"]
            payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        except Exception:
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=True,
                violation_code="malformed_capability_token",
                details="Failed to decode or parse capability token envelope."
            )

        # 1. Verify HMAC Signature
        expected_sig = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=True,
                violation_code="invalid_capability_signature",
                details="Capability token HMAC signature verification failed."
            )

        try:
            claims = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=True,
                violation_code="corrupt_token_claims",
                details="Corrupt inner capability token claims JSON."
            )

        sub = claims.get("sub", "unknown")
        tool = claims.get("tool", "")
        scopes = claims.get("scopes", [])
        exp = claims.get("exp", 0.0)
        nonce = claims.get("nonce", "")

        # 2. Expiration check
        if current_time > exp:
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=True,
                violation_code="expired_capability_token",
                details=f"Capability token expired at {exp} (skew: {current_time - exp:.1f}s).",
                agent_id=sub
            )

        # 3. Nonce replay check
        if nonce in self._consumed_nonces:
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=True,
                violation_code="replayed_capability_nonce",
                details=f"Capability token nonce '{nonce}' has already been consumed.",
                agent_id=sub
            )
        self._consumed_nonces[nonce] = current_time

        # 4. Tool binding check
        if tool != "*" and tool.lower() != expected_tool.lower():
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=True,
                violation_code="unauthorized_tool_binding",
                details=f"Capability token granted for tool '{tool}', but invoked for '{expected_tool}'.",
                agent_id=sub,
                granted_scopes=scopes
            )

        # 5. Required scope check
        if required_scope:
            has_scope = any(
                s == "*" or s == required_scope or (s.endswith(":*") and required_scope.startswith(s[:-1]))
                for s in scopes
            )
            if not has_scope:
                return CapabilityTokenResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="insufficient_capability_scope",
                    details=f"Required scope '{required_scope}' not covered by granted scopes: {scopes}",
                    agent_id=sub,
                    granted_scopes=scopes
                )

        return CapabilityTokenResult(
            is_valid=True,
            is_blocked=False,
            agent_id=sub,
            granted_scopes=scopes
        )

    def inspect_tool_call(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        required_scope: Optional[str] = None,
        now: Optional[float] = None
    ) -> CapabilityTokenResult:
        """Inspects parameters dictionary for capability token and validates it."""
        if not self.enforce_capability_tokens:
            return CapabilityTokenResult(is_valid=True, is_blocked=False)

        token_str = None
        for k in self.CAPABILITY_KEYS:
            if k in parameters and isinstance(parameters[k], str):
                token_str = parameters[k]
                break

        if not token_str:
            return CapabilityTokenResult(
                is_valid=False,
                is_blocked=True,
                violation_code="missing_capability_token",
                details=f"Tool '{tool_name}' invoked without required capability token in arguments."
            )

        return self.verify_token(token_str=token_str, expected_tool=tool_name, required_scope=required_scope, now=now)
