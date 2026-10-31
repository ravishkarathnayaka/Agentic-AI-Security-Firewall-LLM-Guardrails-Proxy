import pytest
from proxy.telemetry.ebpf_telemetry_forwarder import eBPFTelemetryForwarder


def test_ebpf_event_logging():
    fwd = eBPFTelemetryForwarder()
    ev1 = fwd.record_kernel_event(pid=1024, syscall_name="read", target="/var/log/app.log")
    assert ev1.is_anomalous is False
    assert ev1.event_id.startswith("ebpf_")
    assert fwd.get_anomalies_count() == 0


def test_ebpf_anomalous_syscall():
    fwd = eBPFTelemetryForwarder()
    ev2 = fwd.record_kernel_event(pid=2048, syscall_name="ptrace", target="pid_4096", verdict="BLOCKED")
    assert ev2.is_anomalous is True
    assert fwd.get_anomalies_count() == 1
