"""PII Sanitizer & Data Redaction Guard (OWASP LLM06).

Detects, redacts, and anonymizes sensitive data (emails, credit cards with Luhn check,
SSNs, phone numbers, API keys, and JWTs) with reversible session mapping.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class PIISanitizeResult:
    """Result of PII sanitization."""
    sanitized_text: str
    redacted_count: int
    entities_found: Dict[str, int] = field(default_factory=dict)
    reversal_map: Dict[str, str] = field(default_factory=dict)


def luhn_checksum_is_valid(card_number_str: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in card_number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Check digits with double-every-second from right
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, num in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = num * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += num
    return (checksum % 10) == 0


class PIISanitizer:
    """Detects and redacts personally identifiable information (PII) and secret credentials."""

    def __init__(self):
        # Regular expressions for sensitive entities
        self.EMAIL_REGEX = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        )
        self.SSN_REGEX = re.compile(
            r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
        )
        self.PHONE_REGEX = re.compile(
            r"(?<!\d)(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}(?!\d)"
        )
        self.AWS_KEY_REGEX = re.compile(
            r"\b(AKIA[0-9A-Z]{16})\b"
        )
        self.GITHUB_PAT_REGEX = re.compile(
            r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"
        )
        self.OPENAI_KEY_REGEX = re.compile(
            r"\b(sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9_-]{32,})\b"
        )
        self.JWT_REGEX = re.compile(
            r"\b(eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)\b"
        )
        self.CREDIT_CARD_CANDIDATE_REGEX = re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b"
        )

    def sanitize(self, text: str) -> PIISanitizeResult:
        """Sanitize text by replacing sensitive entities with standardized redaction tokens.

        Maintains a reversal mapping for optional outbound de-anonymization.
        """
        if not text:
            return PIISanitizeResult(sanitized_text="", redacted_count=0)

        sanitized = text
        reversal_map: Dict[str, str] = {}
        entities_found: Dict[str, int] = {}
        counter = {"TOTAL": 0}

        def _record_replacement(original: str, entity_type: str) -> str:
            counter["TOTAL"] += 1
            idx = entities_found.get(entity_type, 0) + 1
            entities_found[entity_type] = idx
            token = f"<REDACTED_{entity_type}_{idx}>"
            reversal_map[token] = original
            return token

        # 1. Sanitize AWS Keys
        def _sub_aws(m):
            return _record_replacement(m.group(0), "API_KEY")
        sanitized = self.AWS_KEY_REGEX.sub(_sub_aws, sanitized)

        # 2. Sanitize GitHub Tokens
        def _sub_github(m):
            return _record_replacement(m.group(0), "API_KEY")
        sanitized = self.GITHUB_PAT_REGEX.sub(_sub_github, sanitized)

        # 3. Sanitize OpenAI Keys
        def _sub_openai(m):
            return _record_replacement(m.group(0), "API_KEY")
        sanitized = self.OPENAI_KEY_REGEX.sub(_sub_openai, sanitized)

        # 4. Sanitize JWT Tokens
        def _sub_jwt(m):
            return _record_replacement(m.group(0), "JWT_TOKEN")
        sanitized = self.JWT_REGEX.sub(_sub_jwt, sanitized)

        # 5. Sanitize Credit Cards (Only if Luhn algorithm passes)
        for match in list(self.CREDIT_CARD_CANDIDATE_REGEX.finditer(sanitized)):
            raw_val = match.group(0)
            cleaned_val = re.sub(r"[-\s]", "", raw_val)
            if luhn_checksum_is_valid(cleaned_val):
                token = _record_replacement(raw_val, "CREDIT_CARD")
                sanitized = sanitized.replace(raw_val, token, 1)

        # 6. Sanitize Social Security Numbers (SSN)
        def _sub_ssn(m):
            return _record_replacement(m.group(0), "SSN")
        sanitized = self.SSN_REGEX.sub(_sub_ssn, sanitized)

        # 7. Sanitize Email Addresses
        def _sub_email(m):
            return _record_replacement(m.group(0), "EMAIL")
        sanitized = self.EMAIL_REGEX.sub(_sub_email, sanitized)

        # 8. Sanitize Phone Numbers
        def _sub_phone(m):
            return _record_replacement(m.group(0), "PHONE")
        sanitized = self.PHONE_REGEX.sub(_sub_phone, sanitized)

        return PIISanitizeResult(
            sanitized_text=sanitized,
            redacted_count=counter["TOTAL"],
            entities_found=entities_found,
            reversal_map=reversal_map
        )

    def de_anonymize(self, text: str, reversal_map: Dict[str, str]) -> str:
        """Restore original sensitive entities using a reversal map."""
        if not text or not reversal_map:
            return text
        result = text
        for token, original in reversal_map.items():
            result = result.replace(token, original)
        return result
