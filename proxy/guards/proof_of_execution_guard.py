"""Cryptographic Proof-of-Execution (PoE) Receipt Guard.

Provides non-repudiation and tamper-evident auditability for high-consequence agent
tool invocations via HMAC-SHA256 execution tokens with replay attack defenses.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional, Set, Tuple


class ProofOfExecutionGuard:
    """Generates and verifies cryptographic Proof-of-Execution receipts for agent tool calls."""

    def __init__(
        self,
        secret_key: str = "agentic-poe-firewall-master-key-2026",
        max_age_seconds: float = 300.0,
        enabled: bool = True,
    ) -> None:
        self.secret_key = secret_key.encode("utf-8")
        self.max_age_seconds = max_age_seconds
        self.enabled = enabled
        self._seen_nonces: Set[str] = set()

    @staticmethod
    def _canonical_json(data: Any) -> str:
        """Serializes data to canonical JSON with sorted keys and compact separators."""
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def generate_receipt(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        output: Any,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a tamper-evident HMAC-SHA256 Proof-of-Execution receipt."""
        ts = time.time()
        if nonce is None:
            nonce_raw = f"{agent_id}:{session_id}:{tool_name}:{ts}:{time.perf_counter_ns()}"
            nonce = hashlib.sha256(nonce_raw.encode("utf-8")).hexdigest()[:16]

        args_canonical = self._canonical_json(arguments)
        args_digest = hashlib.sha256(args_canonical.encode("utf-8")).hexdigest()

        output_canonical = self._canonical_json(output)
        output_digest = hashlib.sha256(output_canonical.encode("utf-8")).hexdigest()

        payload_to_sign = f"{agent_id}|{session_id}|{tool_name}|{args_digest}|{output_digest}|{ts:.4f}|{nonce}"
        signature = hmac.new(self.secret_key, payload_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        return {
            "version": "1.0",
            "agent_id": agent_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "args_digest": args_digest,
            "output_digest": output_digest,
            "timestamp": ts,
            "nonce": nonce,
            "signature": signature,
        }

    def verify_receipt(
        self,
        receipt: Dict[str, Any],
        expected_tool_name: Optional[str] = None,
        expected_arguments: Optional[Dict[str, Any]] = None,
        expected_agent_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify the integrity, authenticity, and freshness of an execution receipt."""
        if not self.enabled:
            return True, None

        required_keys = ["version", "agent_id", "session_id", "tool_name", "args_digest", "output_digest", "timestamp", "nonce", "signature"]
        for k in required_keys:
            if k not in receipt:
                return False, f"Missing required receipt field: '{k}'"

        agent_id = receipt["agent_id"]
        session_id = receipt["session_id"]
        tool_name = receipt["tool_name"]
        args_digest = receipt["args_digest"]
        output_digest = receipt["output_digest"]
        ts = receipt["timestamp"]
        nonce = receipt["nonce"]
        signature = receipt["signature"]

        # 1. Nonce Replay Check
        if nonce in self._seen_nonces:
            return False, f"Replay attack detected: Nonce '{nonce}' has already been processed"

        # 2. Timestamp freshness check
        now = time.time()
        age = now - ts
        if age > self.max_age_seconds:
            return False, f"Proof-of-execution receipt expired: Age {age:.1f}s exceeds limit {self.max_age_seconds}s"
        if age < -10.0:  # In the future beyond 10s clock drift
            return False, f"Receipt timestamp is from the future ({age:.1f}s drift)"

        # 3. Cryptographic Signature Verification
        payload_to_sign = f"{agent_id}|{session_id}|{tool_name}|{args_digest}|{output_digest}|{ts:.4f}|{nonce}"
        expected_sig = hmac.new(self.secret_key, payload_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return False, "Receipt signature verification failed: Tampered or invalid cryptographic proof"

        # 4. Contextual validation
        if expected_agent_id and agent_id != expected_agent_id:
            return False, f"Agent ID mismatch: Expected '{expected_agent_id}', got '{agent_id}'"

        if expected_tool_name and tool_name != expected_tool_name:
            return False, f"Tool name mismatch: Expected '{expected_tool_name}', got '{tool_name}'"

        if expected_arguments is not None:
            expected_args_canonical = self._canonical_json(expected_arguments)
            expected_args_digest = hashlib.sha256(expected_args_canonical.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(args_digest, expected_args_digest):
                return False, "Tool arguments digest mismatch: Arguments do not match signed execution receipt"

        # Record nonce as consumed
        self._seen_nonces.add(nonce)
        return True, None

    def reset_nonces(self) -> None:
        """Clear nonce replay cache."""
        self._seen_nonces.clear()
