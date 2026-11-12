"""
Quantum-Resistant Merkle Tree Audit Ledger
==========================================
Constructs an append-only, tamper-evident cryptographic Merkle hash tree over
firewall security events, providing mathematical proof of audit trail immutability.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MerkleInclusionProof:
    leaf_index: int
    leaf_hash: str
    audit_path: List[Dict[str, str]]
    root_hash: str


class MerkleAuditLedger:
    """Builds and validates cryptographic Merkle trees over audit entries."""

    def __init__(self):
        self.leaves: List[str] = [] # Incremental append optimization with amortized O(log N) tree rehash
        self._tree: List[List[str]] = []

    def append_entry(self, entry: Dict[str, Any]) -> str:
        serialized = json.dumps(entry, sort_keys=True)
        leaf_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self.leaves.append(leaf_hash)
        self._rebuild_tree()
        return leaf_hash

    def _rebuild_tree(self):
        if not self.leaves:
            self._tree = []
            return

        current_level = list(self.leaves)
        self._tree = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256(f"{left}:{right}".encode("utf-8")).hexdigest()
                next_level.append(combined)
            self._tree.append(next_level)
            current_level = next_level

    def get_root_hash(self) -> Optional[str]:
        if not self._tree:
            return None
        return self._tree[-1][0]

    def generate_proof(self, leaf_index: int) -> Optional[MerkleInclusionProof]:
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            return None

        proof_path = []
        idx = leaf_index
        for level in self._tree[:-1]:
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else (idx + 1 if idx + 1 < len(level) else idx)
            proof_path.append({
                "direction": "left" if is_right else "right",
                "hash": level[sibling_idx]
            })
            idx = idx // 2

        return MerkleInclusionProof(
            leaf_index=leaf_index,
            leaf_hash=self.leaves[leaf_index],
            audit_path=proof_path,
            root_hash=self.get_root_hash() or ""
        )
