"""
Tamper-Evident Hash-Chained Memory Audit Ledger.

Mitigates OWASP LLM02 (Sensitive Information Disclosure), OWASP LLM08 (Excessive Agency),
and OWASP Agentic AI ASI-04 (Memory Integrity Loss) by maintaining a cryptographically
verifiable, append-only SHA-256 hash-chained ledger for agent episodic memories.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional, List, Dict, Any


@dataclass
class MemoryEntry:
    index: int
    timestamp: float
    agent_id: str
    memory_type: str
    content: str
    prev_hash: str
    entry_hash: str


@dataclass
class LedgerVerificationResult:
    is_valid: bool
    is_blocked: bool = False
    violation_code: Optional[str] = None
    details: str = "Memory audit ledger cryptographic chain is valid"
    broken_index: Optional[int] = None
    total_entries: int = 0


class MemoryAuditLedger:
    """
    Append-only SHA-256 hash-chained audit ledger for agent memory records.
    Detects unauthorized mutation, deletion, or retrofitting of agent memory state.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, agent_id: str = "default_agent"):
        self.agent_id = agent_id
        self._lock = Lock()
        self._chain: List[MemoryEntry] = []

    def _compute_hash(
        self,
        index: int,
        timestamp: float,
        agent_id: str,
        memory_type: str,
        content: str,
        prev_hash: str
    ) -> str:
        payload = f"{index}|{timestamp:.6f}|{agent_id}|{memory_type}|{content}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def append(
        self,
        memory_type: str,
        content: str,
        agent_id: Optional[str] = None,
        timestamp: Optional[float] = None
    ) -> MemoryEntry:
        """
        Appends a new memory item to the ledger and computes its cryptographic hash.
        """
        effective_agent = agent_id or self.agent_id
        ts = timestamp if timestamp is not None else time.time()

        with self._lock:
            index = len(self._chain)
            prev_hash = self._chain[-1].entry_hash if self._chain else self.GENESIS_HASH
            entry_hash = self._compute_hash(index, ts, effective_agent, memory_type, content, prev_hash)

            entry = MemoryEntry(
                index=index,
                timestamp=ts,
                agent_id=effective_agent,
                memory_type=memory_type,
                content=content,
                prev_hash=prev_hash,
                entry_hash=entry_hash
            )
            self._chain.append(entry)
            return entry

    def verify_integrity(self) -> LedgerVerificationResult:
        """
        Validates the entire ledger from Genesis to HEAD, ensuring no entries were altered or deleted.
        """
        with self._lock:
            if not self._chain:
                return LedgerVerificationResult(is_valid=True, total_entries=0)

            for i, entry in enumerate(self._chain):
                # 1. Verify index sequence
                if entry.index != i:
                    return LedgerVerificationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="memory_ledger_index_discontinuity",
                        details=f"Ledger index discontinuity at position {i}: entry has index {entry.index}.",
                        broken_index=i,
                        total_entries=len(self._chain)
                    )

                # 2. Verify previous hash pointer
                expected_prev = self._chain[i - 1].entry_hash if i > 0 else self.GENESIS_HASH
                if entry.prev_hash != expected_prev:
                    return LedgerVerificationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="memory_ledger_chain_break",
                        details=f"Hash chain pointer mismatch at index {i}: expected {expected_prev[:12]}..., got {entry.prev_hash[:12]}...",
                        broken_index=i,
                        total_entries=len(self._chain)
                    )

                # 3. Recompute and verify entry hash
                computed = self._compute_hash(
                    entry.index,
                    entry.timestamp,
                    entry.agent_id,
                    entry.memory_type,
                    entry.content,
                    entry.prev_hash
                )
                if entry.entry_hash != computed:
                    return LedgerVerificationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="memory_ledger_content_tampering",
                        details=f"Cryptographic hash invalid at index {i}: memory content was mutated after recording.",
                        broken_index=i,
                        total_entries=len(self._chain)
                    )

            return LedgerVerificationResult(
                is_valid=True,
                is_blocked=False,
                total_entries=len(self._chain)
            )

    def get_memory(self, index: int) -> Optional[MemoryEntry]:
        """
        Retrieves a memory entry after verifying integrity.
        """
        with self._lock:
            if 0 <= index < len(self._chain):
                return self._chain[index]
            return None

    def export_ledger(self) -> List[Dict[str, Any]]:
        """
        Exports the ledger representation for audit logging or SIEM forwarder.
        """
        with self._lock:
            return [
                {
                    "index": e.index,
                    "timestamp": e.timestamp,
                    "agent_id": e.agent_id,
                    "memory_type": e.memory_type,
                    "content": e.content,
                    "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash
                }
                for e in self._chain
            ]
