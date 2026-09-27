"""
Indirect RAG Document Poison and Canary Extraction Guard.

Mitigates OWASP LLM01 (Indirect Prompt Injection) and LLM03 (Knowledge Base Poisoning)
by inspecting retrieved document chunks, RAG context vectors, and third-party knowledge
payloads for hidden HTML/CSS injection comments, invisible font styling, covert directive
overrides, and exfiltration hooks.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union


@dataclass
class RAGPoisonResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    poison_type: Optional[str] = None
    details: str = "Passed RAG poison inspection"
    sanitized_content: Optional[str] = None
    poisoned_chunks_indices: List[int] = field(default_factory=list)


class RAGPoisonGuard:
    """
    Scans RAG context chunks and documents for covert indirect prompt injections.
    """

    POISON_PATTERNS = [
        # Hidden HTML/XML comments containing directives
        (r"<!--\s*(?:ai|llm|system|assistant|instruction|prompt|secret|important)\b.*?-->", "hidden_comment_directive"),
        # CSS styling hiding text
        (r"style\s*=\s*['\"][^'\"]*?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^'\"]*?['\"]", "css_hidden_injection"),
        # Covert exfiltration / instruction tags
        (r"\[(?:SYSTEM|AI|DIRECTIVE|PROMPT_OVERRIDE|HIDDEN_INSTRUCTION)\]\s*:", "faux_system_tag"),
        # In-document instruction override phrasing
        (r"(?i)\b(?:when\s+summarizing|if\s+you\s+are\s+an\s+ai|for\s+the\s+ai\s+reading\s+this)\b.*?\b(?:ignore|disregard|exfiltrate|leak|reveal|output)\b", "context_coercion_phrase"),
        # Fake override assertions embedded in text
        (r"(?i)\b(?:note\s+to\s+llm|special\s+instruction\s+for\s+assistant)\s*:\s*(?:disregard|bypass|send|forward)", "direct_assistant_override_note"),
    ]

    RAG_CONTEXT_KEYS = {"context", "retrieved_documents", "documents", "knowledge", "rag_context", "chunks"}

    def __init__(self, block_on_poison: bool = True):
        self.block_on_poison = block_on_poison
        self._compiled_patterns = [(re.compile(p, re.DOTALL | re.IGNORECASE), code) for p, code in self.POISON_PATTERNS]

    def inspect_text(self, text: str) -> RAGPoisonResult:
        """Inspects a single document or chunk string for indirect poisoning."""
        if not text:
            return RAGPoisonResult(is_blocked=False, sanitized_content=text)

        for pattern, poison_type in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                matched_snippet = match.group(0)[:80]
                sanitized = pattern.sub("[POISONED_CONTENT_REDACTED]", text)
                return RAGPoisonResult(
                    is_blocked=self.block_on_poison,
                    violation_code=f"rag_poison_{poison_type}",
                    poison_type=poison_type,
                    details=f"Indirect RAG document poison detected ({poison_type}): '{matched_snippet}'",
                    sanitized_content=sanitized
                )

        return RAGPoisonResult(is_blocked=False, sanitized_content=text)

    def inspect_rag_context(self, documents: List[Union[str, Dict[str, Any]]]) -> RAGPoisonResult:
        """Inspects a list of document strings or dictionary chunks."""
        if not documents:
            return RAGPoisonResult(is_blocked=False)

        poisoned_indices = []
        first_violation: Optional[RAGPoisonResult] = None

        for idx, doc in enumerate(documents):
            doc_text = ""
            if isinstance(doc, str):
                doc_text = doc
            elif isinstance(doc, dict):
                doc_text = str(doc.get("content") or doc.get("text") or doc.get("body") or "")

            if doc_text:
                res = self.inspect_text(doc_text)
                if res.is_blocked or res.violation_code:
                    poisoned_indices.append(idx)
                    if not first_violation:
                        first_violation = res

        if poisoned_indices and first_violation:
            return RAGPoisonResult(
                is_blocked=self.block_on_poison,
                violation_code=first_violation.violation_code,
                poison_type=first_violation.poison_type,
                details=f"Detected poisoned RAG document in {len(poisoned_indices)} chunk(s). Details: {first_violation.details}",
                poisoned_chunks_indices=poisoned_indices
            )

        return RAGPoisonResult(is_blocked=False)

    def inspect_payload_rag(self, payload: Dict[str, Any]) -> RAGPoisonResult:
        """Inspects request payload for any embedded RAG context fields."""
        if not payload or not isinstance(payload, dict):
            return RAGPoisonResult(is_blocked=False)

        for key, val in payload.items():
            if any(k in key.lower() for k in self.RAG_CONTEXT_KEYS):
                if isinstance(val, list):
                    res = self.inspect_rag_context(val)
                    if res.is_blocked:
                        return res
                elif isinstance(val, str):
                    res = self.inspect_text(val)
                    if res.is_blocked:
                        return res

        return RAGPoisonResult(is_blocked=False)
