import pytest
from proxy import __version__
from proxy.config import ProxySettings
from proxy.pipeline import SecurityPipeline


def test_v41_version_metadata():
    assert __version__ == "4.1.0"


def test_v41_all_guards_instantiated():
    pipe = SecurityPipeline()
    assert hasattr(pipe, "neuro_symbolic_solver_guard")
    assert hasattr(pipe, "zk_proof_verifier_guard")
    assert hasattr(pipe, "agent_collusion_sybil_guard")
    assert hasattr(pipe, "context_fragmentation_guard")
    assert hasattr(pipe, "semantic_stego_guard")
    assert hasattr(pipe, "hardware_enclave_guard")
    assert hasattr(pipe, "agent_privilege_sandbox_guard")
    assert hasattr(pipe, "ascii_art_guard")
    assert hasattr(pipe, "episodic_memory_decay_guard")
    assert hasattr(pipe, "recursive_reflection_governor")
    assert hasattr(pipe, "differential_privacy_budget_guard")
    assert hasattr(pipe, "agent_action_rollback_journal")
    assert hasattr(pipe, "ebpf_telemetry_forwarder")
    assert hasattr(pipe, "zk_audit_attestation_log")


def test_v41_end_to_end_benign():
    pipe = SecurityPipeline()
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Explain the difference between zk-SNARKs and zk-STARKs."}
        ]
    }
    res = pipe.process_inbound(payload, request_id="rel_val_41_01", client_ip="127.0.0.1")
    assert res.is_allowed is True
