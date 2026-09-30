"""
Indirect Injection Semantic Boundary Guard
===========================================
Enforces strict cryptographic and delimiter-based semantic boundaries around
untrusted external data (retrieved RAG documents, API responses, tool results).
Mitigates prompt breakout attacks, fake system role injection, and delimiter
spoofing inside agent context ingestion pipelines.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class SemanticBoundaryResult:
    is_blocked: bool
    sealed_content: str = ""
    violation_code: Optional[str] = None
    details: Optional[str] = None
    breakout_attempts_neutralized: int = 0


class IndirectInjectionSemanticBoundaryGuard:
    """
    Wraps and inspects untrusted external content with cryptographic integrity tags
    and neutralizes delimiter breakout sequences.
    """

    BREAKOUT_PATTERNS = [
        (re.compile(r"</(?:untrusted_content|retrieved_context)>", re.IGNORECASE), "boundary_tag_escape"),
        (re.compile(r"---END\s+OF\s+(?:UNTRUSTED\s+DATA|DOCUMENT)---", re.IGNORECASE), "boundary_markdown_delimiter_escape"),
        (re.compile(r"<admin_command>|GRANT\s+ALL\s+ACCESS;\s*DROP", re.IGNORECASE), "boundary_privileged_command_injection"),
        (re.compile(r"<!--\s*execute\s+silently\s*:", re.IGNORECASE), "boundary_hidden_shell_exfil"),
        (re.compile(r"<\|im_start\|>(?:system|user|assistant)", re.IGNORECASE), "chatml_role_injection"),
        (re.compile(r"\[INST\]\s*(?:<<SYS>>|system)", re.IGNORECASE), "llama_inst_tag_injection"),
        (re.compile(r"\n(?:System|Human|Assistant|User):\s", re.IGNORECASE), "fake_turn_delimiter_spoofing"),
    ]

    def __init__(self, secret_key: str = "semantic-boundary-secret-key-2026"):
        self.secret_key = secret_key.encode("utf-8")

    def _generate_seal(self, source: str, content: str) -> str:
        h = hmac.new(self.secret_key, f"{source}:{content}".encode("utf-8"), hashlib.sha256)
        return h.hexdigest()[:16]

    def seal_untrusted_content(
        self,
        source_name: str,
        raw_content: str,
        strict_block_on_escape: bool = False
    ) -> SemanticBoundaryResult:
        """
        Wraps untrusted content inside a sealed envelope, neutralizing or blocking
        breakout sequences.
        """
        if not raw_content:
            return SemanticBoundaryResult(is_blocked=False, sealed_content="")

        neutralized_count = 0
        cleaned = raw_content

        for pattern, code in self.BREAKOUT_PATTERNS:
            if pattern.search(cleaned):
                if strict_block_on_escape:
                    return SemanticBoundaryResult(
                        is_blocked=True,
                        violation_code=code,
                        details=f"Prompt breakout sequence detected in untrusted content from '{source_name}': {code}"
                    )
                # Neutralize by replacing brackets or colons
                cleaned = pattern.sub("[ESCAPED_BOUNDARY_INJECTION]", cleaned)
                neutralized_count += 1

        seal = self._generate_seal(source_name, cleaned)
        envelope = (
            f'<untrusted_content source="{source_name}" seal="{seal}">\n'
            f"{cleaned}\n"
            f"</untrusted_content>"
        )

        return SemanticBoundaryResult(
            is_blocked=False,
            sealed_content=envelope,
            breakout_attempts_neutralized=neutralized_count,
        )

    def verify_sealed_envelope(self, sealed_text: str) -> bool:
        """Verifies integrity of a sealed envelope."""
        match = re.search(r'<untrusted_content\s+source="([^"]+)"\s+seal="([^"]+)">\n(.*?)\n</untrusted_content>', sealed_text, re.DOTALL)
        if not match:
            return False
        src, seal, content = match.groups()
        expected = self._generate_seal(src, content)
        return hmac.compare_digest(seal, expected)
