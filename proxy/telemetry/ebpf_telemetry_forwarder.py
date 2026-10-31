"""
eBPF Kernel Telemetry Stream & Structured Audit Forwarder
=========================================================
Captures low-overhead eBPF hook events from agent container syscall boundaries,
emitting structured JSON audit events to kernel monitoring collectors.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class eBPFEvent:
    event_id: str
    timestamp: float
    pid: int
    syscall_name: str
    target_fd_or_path: str
    verdict: str
    is_anomalous: bool = False


class eBPFTelemetryForwarder:
    """
    Aggregates eBPF ring-buffer telemetry and filters kernel-level anomalies.
    """

    def __init__(self, buffer_capacity: int = 1000):
        self.capacity = buffer_capacity
        self.batch_flush_size = 50
        self.events: List[eBPFEvent] = []

    def record_kernel_event(self, pid: int, syscall_name: str, target: str, verdict: str = "ALLOWED") -> eBPFEvent:
        event_id = f"ebpf_{len(self.events)+1:06d}"
        is_anom = verdict != "ALLOWED" or syscall_name in {"ptrace", "pivot_root", "kexec_load"}
        ev = eBPFEvent(
            event_id=event_id,
            timestamp=time.time(),
            pid=pid,
            syscall_name=syscall_name,
            target_fd_or_path=target,
            verdict=verdict,
            is_anomalous=is_anom
        )
        self.events.append(ev)
        if len(self.events) > self.capacity:
            self.events.pop(0)
        return ev

    def get_anomalies_count(self) -> int:
        return sum(1 for e in self.events if e.is_anomalous)
