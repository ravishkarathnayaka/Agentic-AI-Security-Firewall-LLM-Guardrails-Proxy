"""
Agent Egress Domain Allowlist and SSRF Destination Guard.

Mitigates OWASP LLM08 (Excessive Agency) and SSRF by validating that all network requests
and URL parameters initiated by agent tools target explicitly authorized domains,
blocking unapproved external hostnames, cloud metadata services, and internal IP literals.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional, List, Set, Dict, Any
from urllib.parse import urlparse


@dataclass
class EgressAllowlistResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    target_host: Optional[str] = None
    details: str = "Passed egress domain allowlist check"


class EgressDomainAllowlistGuard:
    """
    Enforces perimeter egress policy on agent tool executions involving network requests.
    """

    METADATA_IPS = {
        "169.254.169.254",  # AWS/GCP/Azure link-local metadata
        "fd00:ec2::254",     # AWS IPv6 metadata
        "100.100.100.200",  # Alibaba cloud metadata
    }

    URL_PARAM_KEYS = {"url", "uri", "endpoint", "target", "webhook", "host", "domain", "href"}

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        block_private_ips: bool = True,
        block_ip_literals: bool = True,
        allow_all_egress: bool = False
    ):
        self.allowed_domains: List[str] = [d.lower().strip() for d in (allowed_domains or ["api.github.com", "*.corp.local", "example.com"])]
        self.block_private_ips = block_private_ips
        self.block_ip_literals = block_ip_literals
        self.allow_all_egress = allow_all_egress

    def _is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _is_private_or_loopback(self, hostname: str) -> bool:
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            return False

    def _matches_allowlist(self, hostname: str) -> bool:
        if self.allow_all_egress:
            return True

        host_lower = hostname.lower()
        for pattern in self.allowed_domains:
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if host_lower == suffix or host_lower.endswith("." + suffix):
                    return True
            elif host_lower == pattern:
                return True
        return False

    def inspect_url(self, url: str) -> EgressAllowlistResult:
        """
        Validates a URL against metadata targets, private IPs, and domain allowlist.
        """
        if not url:
            return EgressAllowlistResult(is_blocked=False)

        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            # Handle URLs passed without scheme, e.g. "internal.corp:8080"
            if "://" not in url:
                parsed = urlparse("https://" + url)
                hostname = parsed.hostname

        if not hostname:
            return EgressAllowlistResult(
                is_blocked=True,
                violation_code="malformed_egress_target",
                details=f"Unable to parse valid hostname from destination target: '{url}'"
            )

        hostname = hostname.strip().lower()

        # 1. Cloud metadata service check
        if hostname in self.METADATA_IPS:
            return EgressAllowlistResult(
                is_blocked=True,
                violation_code="cloud_metadata_egress_blocked",
                target_host=hostname,
                details=f"Egress to cloud metadata service endpoint '{hostname}' is strictly forbidden."
            )

        # 2. Private IP / loopback check
        if self.block_private_ips and self._is_private_or_loopback(hostname):
            return EgressAllowlistResult(
                is_blocked=True,
                violation_code="private_ip_egress_blocked",
                target_host=hostname,
                details=f"Destination '{hostname}' resolves to a private, loopback, or link-local address."
            )

        # 3. Raw IP literal blocking
        if self.block_ip_literals and self._is_ip_address(hostname):
            return EgressAllowlistResult(
                is_blocked=True,
                violation_code="ip_literal_egress_blocked",
                target_host=hostname,
                details=f"Direct IP literal '{hostname}' is blocked; FQDN hostname matching allowlist is required."
            )

        # 4. Domain allowlist check
        if not self._matches_allowlist(hostname):
            return EgressAllowlistResult(
                is_blocked=True,
                violation_code="unauthorized_egress_domain",
                target_host=hostname,
                details=f"Destination domain '{hostname}' is not in the approved agent egress allowlist."
            )

        return EgressAllowlistResult(is_blocked=False, target_host=hostname)

    def inspect_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> EgressAllowlistResult:
        """
        Inspects agent tool parameters for any URL or endpoint fields that violate egress policy.
        """
        if not parameters or not isinstance(parameters, dict):
            return EgressAllowlistResult(is_blocked=False)

        for key, val in parameters.items():
            if any(k in key.lower() for k in self.URL_PARAM_KEYS) and isinstance(val, str):
                result = self.inspect_url(val)
                if result.is_blocked:
                    return result

        return EgressAllowlistResult(is_blocked=False)
