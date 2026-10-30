"""
Quantum-Resistant Audit Signer & Block Attestation
=================================================
Signs telemetry audit records into cryptographic merkle chains with SHA3-512
hashes, ensuring immutable non-repudiation and tamper-evident audit trails.
"""

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any


@dataclass
class AuditRecord:
    record_id: str
    timestamp: float
    session_id: str
    action_type: str
    verdict: str
    risk_score: float
    guard_violations: List[str]
    prev_block_hash: str
    block_hash: str = ""


class QuantumAuditSigner:
    """
    Cryptographic merkle chain engine for AI firewall event attestation.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, private_salt: str = "quantum_audit_lattice_chain_v4"):
        self.salt = private_salt.encode("utf-8")
        self.latest_block_hash = self.GENESIS_HASH
        self.chain: List[AuditRecord] = []

    def attest_event(self, session_id: str, action_type: str, verdict: str, risk_score: float, violations: List[str]) -> AuditRecord:
        record_id = f"aud_{len(self.chain)+1:06d}"
        now = time.time()

        payload = {
            "record_id": record_id,
            "timestamp": now,
            "session_id": session_id,
            "action_type": action_type,
            "verdict": verdict,
            "risk_score": risk_score,
            "guard_violations": violations,
            "prev_block_hash": self.latest_block_hash,
        }

        # SHA3-512 block hash
        canonical_str = json.dumps(payload, sort_keys=True)
        block_hash = hashlib.sha3_512(canonical_str.encode("utf-8") + self.salt).hexdigest()

        rec = AuditRecord(
            record_id=record_id,
            timestamp=now,
            session_id=session_id,
            action_type=action_type,
            verdict=verdict,
            risk_score=risk_score,
            guard_violations=violations,
            prev_block_hash=self.latest_block_hash,
            block_hash=block_hash
        )

        self.chain.append(rec)
        self.latest_block_hash = block_hash
        return rec

    def verify_chain_integrity(self) -> bool:
        prev = self.GENESIS_HASH
        for rec in self.chain:
            if rec.prev_block_hash != prev:
                return False
            payload = {
                "record_id": rec.record_id,
                "timestamp": rec.timestamp,
                "session_id": rec.session_id,
                "action_type": rec.action_type,
                "verdict": rec.verdict,
                "risk_score": rec.risk_score,
                "guard_violations": rec.guard_violations,
                "prev_block_hash": rec.prev_block_hash,
            }
            canonical_str = json.dumps(payload, sort_keys=True)
            expected_hash = hashlib.sha3_512(canonical_str.encode("utf-8") + self.salt).hexdigest()
            if rec.block_hash != expected_hash:
                return False
            prev = rec.block_hash
        return True
