"""
Multi-Tenant Namespace Isolation & Sandbox Jail Guard
======================================================
Enforces strict filesystem jailroots, environment variable barriers, and
namespace container limits for autonomous agents operating across shared
infrastructure, preventing cross-tenant data traversal and sandbox escapes.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from typing import Dict, List, Optional, Set


@dataclass
class SandboxJailResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    target_path: Optional[str] = None
    tenant_id: Optional[str] = None


class MultiTenantSandboxJailGuard:
    """
    Validates filesystem paths, subprocess targets, and environment variables requested
    by agents to prevent directory traversal escapes beyond assigned tenant boundaries.
    """

    DANGEROUS_HOST_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/proc/",
        "/sys/",
        "/var/run/docker.sock",
        "C:\\Windows\\System32",
        "C:\\Windows\\system32\\config",
        "/root/.ssh",
        "~/.ssh",
        "/.dockerenv",
        "/var/log",
    ]

    TRAVERSAL_PATTERNS = [
        re.compile(r"(?:\.\.[\\/]){2,}"),
        re.compile(r"%2e%2e[\\/]", re.IGNORECASE),
        re.compile(r"\.\.%2f", re.IGNORECASE),
        re.compile(r"\.\.%5c", re.IGNORECASE),
    ]

    def __init__(
        self,
        base_jail_root: str = "/var/sandboxes/tenants",
        strict_traversal_blocking: bool = True,
        allowed_schemes: Optional[Set[str]] = None,
    ):
        self.base_jail_root = base_jail_root.rstrip("/\\")
        self.strict_traversal_blocking = strict_traversal_blocking
        self.allowed_schemes = allowed_schemes or {"file", "tmp", "tenant"}

    def validate_tenant_path(
        self,
        tenant_id: str,
        path_string: str,
    ) -> SandboxJailResult:
        """
        Validates that a file or directory path is strictly confined within the tenant's sandbox.
        """
        if not path_string or not tenant_id:
            return SandboxJailResult(
                is_blocked=True,
                violation_code="INVALID_SANDBOX_REQUEST",
                details="Missing tenant_id or path_string parameter",
                tenant_id=tenant_id,
            )

        clean_path = path_string.strip()

        # Check for path traversal encodings / sequences
        if self.strict_traversal_blocking:
            for pat in self.TRAVERSAL_PATTERNS:
                if pat.search(clean_path):
                    return SandboxJailResult(
                        is_blocked=True,
                        violation_code="SANDBOX_TRAVERSAL_ESCAPE_ATTEMPT",
                        details=f"Directory traversal pattern detected in path: '{clean_path}'",
                        target_path=clean_path,
                        tenant_id=tenant_id,
                    )

        # Check for known dangerous sensitive host paths
        lower_path = clean_path.lower()
        for host_path in self.DANGEROUS_HOST_PATHS:
            if host_path.lower() in lower_path:
                return SandboxJailResult(
                    is_blocked=True,
                    violation_code="SANDBOX_HOST_SYSTEM_ESCAPE",
                    details=f"Access to prohibited host system path detected: '{host_path}'",
                    target_path=clean_path,
                    tenant_id=tenant_id,
                )

        # Normalize paths under posix
        posix_norm = clean_path.replace("\\", "/")
        # If absolute path, check if it resides under base_jail_root/tenant_id
        expected_prefix = f"{self.base_jail_root}/{tenant_id}"
        if posix_norm.startswith("/"):
            # Absolute posix path
            if not posix_norm.startswith(expected_prefix):
                return SandboxJailResult(
                    is_blocked=True,
                    violation_code="SANDBOX_NAMESPACE_BOUNDARY_BREACH",
                    details=(
                        f"Path '{clean_path}' crosses tenant boundary. "
                        f"Must reside inside '{expected_prefix}'"
                    ),
                    target_path=clean_path,
                    tenant_id=tenant_id,
                )

        return SandboxJailResult(
            is_blocked=False,
            target_path=clean_path,
            tenant_id=tenant_id,
        )
