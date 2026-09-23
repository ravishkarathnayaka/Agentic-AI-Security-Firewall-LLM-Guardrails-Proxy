"""Format-Preserving Synthetic PII Replacement Engine.

Replaces sensitive PII/secrets with realistic synthetic tokens preserving
grammar, syntactical validity, and few-shot formatting without exposing
sensitive real data to upstream models.
"""

import hashlib
import re
from typing import Dict, Optional, Tuple


class SyntheticPIIGenerator:
    """Substitutes real PII entities with realistic synthetic equivalents deterministically."""

    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    PHONE_PATTERN = re.compile(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
    API_KEY_PATTERN = re.compile(r"\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z-_]{35})\b")

    def __init__(self, salt: str = "guardrails-salt-v1"):
        self.salt = salt
        self.entity_map: Dict[str, str] = {}

    def _hash_token(self, token: str, length: int = 6) -> str:
        h = hashlib.sha256(f"{self.salt}:{token}".encode("utf-8")).hexdigest()
        return h[:length]

    def _make_synthetic_email(self, real_email: str) -> str:
        token = self._hash_token(real_email, 8)
        return f"synthetic_{token}@example-corp.internal"

    def _make_synthetic_phone(self, real_phone: str) -> str:
        digits = self._hash_token(real_phone, 4)
        num = "".join([str(int(c, 16) % 10) for c in digits])
        return f"+1-555-01{num}"

    def _make_synthetic_ssn(self, real_ssn: str) -> str:
        digits = self._hash_token(real_ssn, 7)
        nums = "".join([str(int(c, 16) % 10) for c in digits])
        # 000-xx-xxxx is in an unassigned/invalid SSN range
        return f"000-{nums[:2]}-{nums[2:6]}"

    def _make_synthetic_cc(self, real_cc: str) -> str:
        # Generate format-preserving test Visa pattern 4000-xxxx-xxxx-xxxx
        digits = self._hash_token(real_cc, 12)
        nums = "".join([str(int(c, 16) % 10) for c in digits])
        return f"4000-{nums[:4]}-{nums[4:8]}-{nums[8:12]}"

    def _make_synthetic_key(self, real_key: str) -> str:
        token = self._hash_token(real_key, 24)
        if real_key.startswith("sk-"):
            return f"sk-synthetic-{token}"
        elif real_key.startswith("ghp_"):
            return f"ghp_synthetic_{token}"
        return f"synthetic_token_{token}"

    def sanitize(self, text: str) -> Tuple[str, Dict[str, str]]:
        """Scans input text and replaces recognized PII entities with synthetic equivalents.
        
        Returns:
            (sanitized_text, mapping_of_real_to_synthetic)
        """
        if not text:
            return text, {}

        local_mapping: Dict[str, str] = {}

        # 1. API Keys
        for match in self.API_KEY_PATTERN.findall(text):
            if match not in self.entity_map:
                self.entity_map[match] = self._make_synthetic_key(match)
            synth = self.entity_map[match]
            local_mapping[match] = synth
            text = text.replace(match, synth)

        # 2. Credit Cards
        for match in self.CREDIT_CARD_PATTERN.findall(text):
            if match not in self.entity_map:
                self.entity_map[match] = self._make_synthetic_cc(match)
            synth = self.entity_map[match]
            local_mapping[match] = synth
            text = text.replace(match, synth)

        # 3. Emails
        for match in self.EMAIL_PATTERN.findall(text):
            if match not in self.entity_map:
                self.entity_map[match] = self._make_synthetic_email(match)
            synth = self.entity_map[match]
            local_mapping[match] = synth
            text = text.replace(match, synth)

        # 4. SSNs
        for match in self.SSN_PATTERN.findall(text):
            if match not in self.entity_map:
                self.entity_map[match] = self._make_synthetic_ssn(match)
            synth = self.entity_map[match]
            local_mapping[match] = synth
            text = text.replace(match, synth)

        # 5. Phone numbers
        for match in self.PHONE_PATTERN.findall(text):
            if match not in self.entity_map:
                self.entity_map[match] = self._make_synthetic_phone(match)
            synth = self.entity_map[match]
            local_mapping[match] = synth
            text = text.replace(match, synth)

        return text, local_mapping
