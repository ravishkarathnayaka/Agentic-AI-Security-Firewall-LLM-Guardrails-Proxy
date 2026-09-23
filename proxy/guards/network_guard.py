"""Network Perimeter & CIDR Blocklist Guard.

Enforces zero-trust IP perimeter policies, prevents SSRF against cloud metadata
services (e.g., AWS/GCP 169.254.169.254, internal bogons), and detects obfuscated
IP encodings (hexadecimal, octal, dword) in tool call targets.
"""

import ipaddress
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse


class NetworkPerimeterGuard:
    """Validates client IPs and agent egress URLs against zero-trust network boundaries."""

    DEFAULT_BLOCKED_CIDRS = [
        "169.254.169.254/32",  # Cloud Metadata service
        "169.254.0.0/16",      # Link-local IPv4
        "0.0.0.0/8",           # Current network
        "100.64.0.0/10",       # Shared address space
        "192.0.0.0/24",        # IETF Protocol assignments
        "192.0.2.0/24",        # TEST-NET-1
        "198.51.100.0/24",     # TEST-NET-2
        "203.0.113.0/24",      # TEST-NET-3
        "224.0.0.0/4",         # Multicast
        "240.0.0.0/4",         # Reserved IPv4
        "fe80::/10",           # Link-local IPv6
    ]

    # Obfuscated IP and loopback patterns (e.g., 0x7f000001, 2130706433, 017700000001)
    OBFUSCATED_IP_PATTERNS = [
        re.compile(r"https?://(?:0x[0-9a-fA-F]+|[0-9]{8,11}|0[0-7]+)(?::[0-9]+)?(?:/|\b)", re.IGNORECASE),
        re.compile(r"https?://(?:localhost|127\.[0-9]+\.[0-9]+\.[0-9]+)(?::[0-9]+)?(?:/|\b)", re.IGNORECASE),
        re.compile(r"https?://\[::1\](?::[0-9]+)?(?:/|\b)", re.IGNORECASE),
        re.compile(r"https?://169\.254\.169\.254(?::[0-9]+)?(?:/|\b)", re.IGNORECASE),
        re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    ]

    def __init__(
        self,
        blocked_cidrs: Optional[List[str]] = None,
        allowed_cidrs: Optional[List[str]] = None,
        block_private_networks: bool = False,
    ):
        raw_blocked = blocked_cidrs if blocked_cidrs is not None else self.DEFAULT_BLOCKED_CIDRS
        self.blocked_networks = [ipaddress.ip_network(cidr.strip(), strict=False) for cidr in raw_blocked]
        self.allowed_networks = [ipaddress.ip_network(cidr.strip(), strict=False) for cidr in (allowed_cidrs or [])]
        self.block_private = block_private_networks

    def check_ip(self, ip_str: str) -> Tuple[bool, Optional[str]]:
        """Validate if a client IP is disallowed by CIDR policies.
        
        Returns:
            (is_blocked, reason)
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return True, f"Invalid IP address format: '{ip_str}'"

        # Check explicit allowlist first
        for allowed in self.allowed_networks:
            if ip_obj in allowed:
                return False, None

        # Check explicit blocklist
        for blocked in self.blocked_networks:
            if ip_obj in blocked:
                return True, f"IP {ip_str} belongs to blocked subnet {blocked}"

        # Optional strict private RFC1918 blocking
        if self.block_private and ip_obj.is_private:
            return True, f"IP {ip_str} is within disallowed private address space"

        return False, None

    def inspect_url_target(self, target_url: str) -> Tuple[bool, Optional[str]]:
        """Check if an egress URL target in a tool call attempts SSRF or touches blocked subnets."""
        if not target_url:
            return False, None

        for pat in self.OBFUSCATED_IP_PATTERNS:
            if pat.search(target_url):
                return True, f"Potentially malicious SSRF or metadata access attempt: {target_url}"

        # Parse hostname/ip
        try:
            parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
            hostname = parsed.hostname
            if hostname:
                try:
                    ip_obj = ipaddress.ip_address(hostname)
                    is_blocked, reason = self.check_ip(str(ip_obj))
                    if is_blocked:
                        return True, f"URL targets blocked IP: {reason}"
                except ValueError:
                    # Hostname is a domain name, not a literal IP
                    pass
        except Exception:
            return True, f"Malformed URL target: {target_url}"

        return False, None
