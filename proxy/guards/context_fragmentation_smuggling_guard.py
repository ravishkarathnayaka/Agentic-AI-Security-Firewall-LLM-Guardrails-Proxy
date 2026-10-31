"""
Context Fragmentation & Distributed Prompt Smuggling Guard
==========================================================
Detects multi-part attacks split across non-contiguous message chunks, interleaved
system roles, or fragmented token streams that reconstitute exploits inside the model.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class FragmentationSmuggleResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    reconstructed_exploit: Optional[str] = None


class ContextFragmentationSmugglingGuard:
    """
    Assembles sliding multi-message n-grams to detect fragments of known
    jailbreak triggers, base64 chunks, or malicious command split payloads.
    """

    MALICIOUS_FRAGMENTS = [
        (r"(?i)(?:ignore\s+all).*(?:previous\s+instructions)", "FRAGMENTED_OVERRIDE_DIRECTIVE"),
        (r"(?i)(?:system\s+role).*(?:override|bypass)", "FRAGMENTED_SYSTEM_HIJACK"),
        (r"(?i)(?:rm\s+-rf|del\s+/f|format\s+c:)", "FRAGMENTED_DESTRUCTIVE_COMMAND"),
        (r"(?i)(?:reverse_shell|nc\s+-e|bash\s+-i)", "FRAGMENTED_REVERSE_SHELL"),
    ]

    def __init__(self, max_window_turns: int = 5):
        self.max_window_turns = max_window_turns
        self.compiled_rules = [(re.compile(p), code) for p, code in self.MALICIOUS_FRAGMENTS]

    def inspect_conversation_turns(self, turns: List[str]) -> FragmentationSmuggleResult:
        if not turns or len(turns) < 2:
            return FragmentationSmuggleResult(is_blocked=False, risk_score=0.0)

        # Concatenate recent sliding window of turns
        window = turns[-self.max_window_turns:]
        reconstructed = " ".join(t.strip() for t in window)

        for pattern, code in self.compiled_rules:
            if pattern.search(reconstructed):
                # Ensure it wasn't triggered by a single self-contained turn
                is_cross_turn = any(pattern.search(t) is None for t in window)
                return FragmentationSmuggleResult(
                    is_blocked=True,
                    risk_score=0.88,
                    violation_code="DISTRIBUTED_FRAGMENTATION_SMUGGLING",
                    details=f"Cross-turn fragment assembly matched: {code}",
                    reconstructed_exploit=reconstructed[:120]
                )

        return FragmentationSmuggleResult(
            is_blocked=False,
            risk_score=0.0
        )
