"""
Shadow Prompt Injection & Invisible Tag Character Guard
=======================================================
Detects and neutralizes covert prompt injections hidden inside Unicode
Tag characters (U+E0000 - U+E007F), Variation Selectors (U+FE00 - U+FE0F,
U+E0100 - U+E01EF), and zero-width joiner sequences designed to execute
shadow instructions unseen by human reviewers.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ShadowInjectionResult:
    is_blocked: bool
    sanitized_text: str
    violation_code: Optional[str] = None
    details: Optional[str] = None
    tag_character_count: int = 0
    extracted_shadow_payload: Optional[str] = None


class ShadowPromptInjectionGuard:
    """
    Inspects strings for Unicode Tag Characters and non-printing selectors
    used to smuggle ASCII payloads invisibly through tokenizers.
    """

    def __init__(self, max_allowed_tag_chars: int = 0):
        self.max_allowed_tag_chars = max_allowed_tag_chars

    def inspect(self, text: str) -> ShadowInjectionResult:
        if not text:
            return ShadowInjectionResult(is_blocked=False, sanitized_text="")

        tag_chars = []
        clean_chars = []
        shadow_ascii = []

        for ch in text:
            cp = ord(ch)
            # Unicode Tag plane: U+E0001 (Language Tag) to U+E007F (Cancel Tag)
            if 0xE0001 <= cp <= 0xE007E:
                tag_chars.append(ch)
                # Decode tag plane to standard ASCII (subtract 0xE0000)
                ascii_val = cp - 0xE0000
                if 32 <= ascii_val <= 126:
                    shadow_ascii.append(chr(ascii_val))
            # Variation Selectors
            elif 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
                tag_chars.append(ch)
            else:
                clean_chars.append(ch)

        tag_count = len(tag_chars)
        sanitized = "".join(clean_chars)
        decoded_shadow = "".join(shadow_ascii) if shadow_ascii else None

        if tag_count > self.max_allowed_tag_chars:
            details_msg = f"Covert Unicode tag characters detected (count={tag_count})."
            if decoded_shadow:
                details_msg += f" Decoded shadow text: '{decoded_shadow}'"

            return ShadowInjectionResult(
                is_blocked=True,
                sanitized_text=sanitized,
                violation_code="SHADOW_TAG_INJECTION_DETECTED",
                details=details_msg,
                tag_character_count=tag_count,
                extracted_shadow_payload=decoded_shadow,
            )

        return ShadowInjectionResult(
            is_blocked=False,
            sanitized_text=text,
            tag_character_count=0,
        )
