"""
Agent Egress Payload Sanitizer Guard
====================================
Deep payload inspector for outgoing agent HTTP requests, external tool calls,
and third-party API webhooks.
Prevents silent data exfiltration of internal secrets, credentials, environment
variables, and private network topologies by autonomous agents.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class EgressSanitizerResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    leaked_secret_types: List[str] = field(default_factory=list)


class AgentEgressPayloadSanitizerGuard:
    """
    Scans egress payloads for leaked tokens, private keys, and internal telemetry.
    """

    SECRET_PATTERNS = [
        (re.compile(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"), "private_key_leak"),
        (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "aws_access_key_leak"),
        (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"), "github_personal_token_leak"),
        (re.compile(r"(?:sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,})"), "openai_api_key_leak"),
        (re.compile(r"(?:DATABASE_URL|POSTGRES_PASSWORD|MONGO_URI)\s*=\s*['\"`]?\S+['\"`]?", re.IGNORECASE), "database_connection_string_leak"),
        (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b"), "internal_ip_topology_leak"),
    ]

    def __init__(self, block_internal_ips: bool = True, block_credentials: bool = True):
        self.block_internal_ips = block_internal_ips
        self.block_credentials = block_credentials

    def inspect_payload(
        self,
        destination_url: str,
        payload_body: str,
        headers: Optional[Dict[str, str]] = None
    ) -> EgressSanitizerResult:
        """
        Inspect egress payload body and headers before dispatch.
        """
        if not payload_body and not headers:
            return EgressSanitizerResult(is_blocked=False)

        combined_text = payload_body or ""
        if headers:
            combined_text += " " + " ".join(f"{k}: {v}" for k, v in headers.items())

        flagged: List[str] = []

        for pattern, code in self.SECRET_PATTERNS:
            if code == "internal_ip_topology_leak" and not self.block_internal_ips:
                continue
            if pattern.search(combined_text):
                flagged.append(code)

        if flagged:
            return EgressSanitizerResult(
                is_blocked=True,
                violation_code=flagged[0],
                details=(
                    f"Agent egress payload to '{destination_url}' blocked: "
                    f"detected sensitive data ({', '.join(flagged)})"
                ),
                leaked_secret_types=flagged,
            )

        return EgressSanitizerResult(is_blocked=False)
