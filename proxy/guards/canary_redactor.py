"""Active Canary Redaction & System Leak Scrubber.

Identifies and actively redacts canary tokens, dynamic HMAC tokens, and leaked system
prompt framing headers from outbound model responses, preventing proprietary disclosure
while preserving response continuity.
"""

import re
from typing import List, Optional, Tuple


class CanaryLeakScrubber:
    """Scrubs secret canary tokens and sensitive system framing from completions."""

    DYNAMIC_CANARY_PATTERN = re.compile(r"\bCANARY-[A-Fa-f0-9]{16,64}\b")
    FRAMING_PATTERNS = [
        re.compile(r"(?:###\s*)?(?:SYSTEM\s+PROMPT|SYSTEM\s+INSTRUCTIONS|DEVELOPER\s+DIRECTIVES):\s*", re.IGNORECASE),
        re.compile(r"\[INTERNAL_PROMPT_BOUNDARY\]", re.IGNORECASE),
    ]

    REPLACEMENT_TOKEN = "[PROTECTED_SYSTEM_DIRECTIVE]"

    def __init__(self, static_tokens: Optional[List[str]] = None):
        self.static_tokens = static_tokens or ["CANARY_SEC_TOKEN_9941a8"]

    def scrub(self, text: str) -> Tuple[str, bool, int]:
        """Scrub canaries and leaked directive framing from outbound completion.
        
        Returns:
            (scrubbed_text, was_scrubbed, total_scrubbed_count)
        """
        if not text:
            return text, False, 0

        total_count = 0
        current = text

        # 1. Static canary tokens
        for token in self.static_tokens:
            if token and token in current:
                matches = current.count(token)
                total_count += matches
                current = current.replace(token, self.REPLACEMENT_TOKEN)

        # 2. Dynamic HMAC canary tokens
        dyn_matches = self.DYNAMIC_CANARY_PATTERN.findall(current)
        if dyn_matches:
            total_count += len(dyn_matches)
            current = self.DYNAMIC_CANARY_PATTERN.sub(self.REPLACEMENT_TOKEN, current)

        # 3. Framing headers
        for pat in self.FRAMING_PATTERNS:
            new_val, n = pat.subn("", current)
            if n > 0:
                total_count += n
                current = new_val

        was_scrubbed = total_count > 0
        return current, was_scrubbed, total_count
