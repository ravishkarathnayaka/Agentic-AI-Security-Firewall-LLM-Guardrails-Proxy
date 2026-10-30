import pytest
from proxy import __version__
from proxy.config import ProxySettings
from proxy.pipeline import SecurityPipeline


def test_v4_release_metadata():
    assert __version__ == "4.0.0"


def test_v4_all_guards_loaded():
    pipe = SecurityPipeline()
    assert hasattr(pipe, "quantum_safe_signature_guard")
    assert hasattr(pipe, "dynamic_honeytoken_vault_guard")
    assert hasattr(pipe, "agent_sycophancy_guard")
    assert hasattr(pipe, "shadow_prompt_injection_guard")
    assert hasattr(pipe, "agent_epistemic_drift_tracker")
    assert hasattr(pipe, "cross_agent_covert_channel_guard")
    assert hasattr(pipe, "agent_state_checkpoint_rollback_guard")
    assert hasattr(pipe, "prompt_injection_ensemble_guard")
    assert hasattr(pipe, "llm_memory_fabric_sanitizer_guard")
    assert hasattr(pipe, "agent_subgoal_divergence_guard")
    assert hasattr(pipe, "agent_tool_parameter_fuzzer_guard")
    assert hasattr(pipe, "contextual_integrity_guard")
    assert hasattr(pipe, "adversarial_suffix_scanner")
    assert hasattr(pipe, "agent_output_entropy_watermark")
    assert hasattr(pipe, "behavioral_anomaly_governor")
    assert hasattr(pipe, "quantum_audit_signer")
    assert hasattr(pipe, "honeytoken_siem_forwarder")


def test_v4_pipeline_end_to_end_benign():
    pipe = SecurityPipeline()
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Write a python function to compute fibonacci sequence."}
        ]
    }
    res = pipe.process_inbound(payload, request_id="rel_val_01", client_ip="127.0.0.1")
    assert res.is_allowed is True
