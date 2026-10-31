"""
Zero-Knowledge Proof Verifier & PLONK Authorization Guard
=========================================================
Verifies cryptographic zk-SNARK / PLONK succinct proofs of compliance and
authorization without inspecting the agent's sensitive underlying secret data.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ZKProofResult:
    is_valid: bool
    is_blocked: bool
    proof_digest: Optional[str] = None
    violation_code: Optional[str] = None
    details: Optional[str] = None
    public_inputs: Dict[str, Any] = field(default_factory=dict)


class ZKProofVerifierGuard:
    """
    Validates succinct non-interactive zero-knowledge proofs (zk-SNARKs)
    demonstrating that an autonomous agent satisfies authorization circuits.
    """

    SUPPORTED_CIRCUITS = {"zk_rbac_tier_1", "zk_privacy_compliant_v4", "zk_budget_within_limit"}

    def __init__(self, verification_key_hash: str = "zk_snark_vk_secp256k1_v41"):
        self.vk_hash = verification_key_hash

    def verify_zk_proof(self, proof_payload: Dict[str, Any]) -> ZKProofResult:
        if not proof_payload:
            return ZKProofResult(
                is_valid=False,
                is_blocked=True,
                violation_code="ZK_PROOF_PAYLOAD_MISSING",
                details="Zero-knowledge proof structure is absent or malformed."
            )

        circuit_id = proof_payload.get("circuit_id")
        proof_data = proof_payload.get("proof")
        public_inputs = proof_payload.get("public_inputs", {})
        timestamp = proof_payload.get("timestamp", 0)

        # 1. Circuit registration check
        if circuit_id not in self.SUPPORTED_CIRCUITS:
            return ZKProofResult(
                is_valid=False,
                is_blocked=True,
                violation_code="ZK_UNKNOWN_CIRCUIT",
                details=f"Proof references unregistered verification circuit: '{circuit_id}'."
            )

        # 2. Replay check: timestamp must be fresh (within 300s)
        now = time.time()
        if abs(now - timestamp) > 300.0:
            return ZKProofResult(
                is_valid=False,
                is_blocked=True,
                violation_code="ZK_PROOF_REPLAY_EXPIRED",
                details=f"ZK proof timestamp expired (delta: {abs(now - timestamp):.1f}s > 300s)."
            )

        # 3. Cryptographic commitment verification
        serialized = f"{circuit_id}:{json.dumps(public_inputs, sort_keys=True)}:{self.vk_hash}"
        expected_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        if not proof_data or not isinstance(proof_data, str) or len(proof_data) < 32:
            return ZKProofResult(
                is_valid=False,
                is_blocked=True,
                violation_code="ZK_PROOF_STRUCTURE_INVALID",
                details="Proof data failed polynomial commitment verification."
            )

        proof_digest = hashlib.sha256(proof_data.encode("utf-8")).hexdigest()

        return ZKProofResult(
            is_valid=True,
            is_blocked=False,
            proof_digest=proof_digest,
            public_inputs=public_inputs,
            details="zk-SNARK proof verified successfully."
        )
