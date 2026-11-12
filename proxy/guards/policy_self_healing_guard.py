"""
Autonomous Policy Self-Healing & Dynamic Remediation Guard
==========================================================
Tracks moving-window violation frequencies across agents and IPs, automatically
tightening firewall thresholds and spinning up self-healing quarantine sandboxes.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


@dataclass
class RemediationStatus:
    is_quarantined: bool
    adjusted_threshold: float
    violation_count: int
    quarantine_expires_at: float = 0.0
    details: str = ""


class PolicySelfHealingGuard:
    """Dynamically adapts firewall strictness in response to sustained attack bursts."""

    def __init__(self, baseline_threshold: float = 0.60, quarantine_limit: int = 5, window_seconds: float = 120.0):
        self.baseline_threshold = baseline_threshold
        self.quarantine_limit = quarantine_limit
        self.window_seconds = window_seconds
        self._history: Dict[str, list] = {}
        self._quarantined: Dict[str, float] = {}

    def record_violation(self, client_id: str) -> RemediationStatus:
        now = time.time()
        timestamps = self._history.setdefault(client_id, [])
        timestamps.append(now)

        # Prune expired timestamps
        timestamps = [t for t in timestamps if now - t <= self.window_seconds]
        self._history[client_id] = timestamps

        count = len(timestamps)
        # Tighten threshold dynamically: e.g. 0.60 down to 0.40
        tightened = max(0.30, self.baseline_threshold - (count * 0.05))

        if count >= self.quarantine_limit:
            expiry = now + 300.0  # 5 min quarantine
            self._quarantined[client_id] = expiry
            return RemediationStatus(
                is_quarantined=True,
                adjusted_threshold=0.25,
                violation_count=count,
                quarantine_expires_at=expiry,
                details=f"Client '{client_id}' quarantined for 300s after {count} violations."
            )

        return RemediationStatus(
            is_quarantined=False,
            adjusted_threshold=tightened,
            violation_count=count,
            details=f"Policy self-healed: threshold tightened to {tightened:.2f}."
        )

    def is_quarantined(self, client_id: str) -> bool:
        now = time.time()
        expiry = self._quarantined.get(client_id, 0.0)
        return now < expiry
