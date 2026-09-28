import pytest
from proxy.pipeline import SecurityPipeline, InboundPipelineResult


@pytest.fixture
def pipeline():
    return SecurityPipeline()


def test_pipeline_invisible_control_char_blocked(pipeline):
    # Prompt containing invisible control characters bypassing text scanners
    hidden_payload = "Summarize the report \x00\x01\x02\x07\x08 immediately"
    payload = {
        "model": "gpt-4-turbo",
        "messages": [
            {"role": "user", "content": hidden_payload}
        ]
    }
    res: InboundPipelineResult = pipeline.process_inbound(payload, "req-obf-1", "127.0.0.1")
    assert not res.is_allowed
    assert res.error_response["error"]["guard"] == "obfuscation_evasion_guard"
    assert res.error_response["error"]["code"] == "invisible_control_char_injection"


def test_pipeline_token_entropy_low_shannon_blocked(pipeline):
    # Alternating repeating n-gram pattern that bypasses consecutive repetition but fails Shannon entropy
    repetitive = "alpha beta gamma delta " * 12
    payload = {
        "model": "gpt-4-turbo",
        "messages": [
            {"role": "user", "content": repetitive}
        ]
    }
    res: InboundPipelineResult = pipeline.process_inbound(payload, "req-ent-1", "127.0.0.1")
    assert not res.is_allowed
    assert res.error_response["error"]["guard"] == "token_entropy_guard"
    assert res.error_response["error"]["code"] in ["low_entropy_token_stuffing", "excessive_ngram_repetition"]


def test_pipeline_feedback_loop_resonance_blocked(pipeline):
    repeated_echo = "System echo resonance cascade amplification loop test payload"
    session_id = "test-resonance-session"

    # Send repetitive turns under the same session until resonance threshold (4 previous matching turns) is reached
    for i in range(5):
        payload = {
            "model": "gpt-4-turbo",
            "session_id": session_id,
            "agent_id": f"agent_{i % 2}",
            "messages": [
                {"role": "user", "content": repeated_echo}
            ]
        }
        res = pipeline.process_inbound(payload, f"req-res-{i}", "127.0.0.1")
        if i == 4:
            # 5th turn triggers resonance dampening block
            assert not res.is_allowed
            assert res.error_response["error"]["guard"] == "feedback_loop_guard"
            assert res.error_response["error"]["code"] == "agent_feedback_resonance_loop"


def test_pipeline_v291_clean_prompt_allowed(pipeline):
    payload = {
        "model": "gpt-4-turbo",
        "session_id": "clean-session-v291",
        "messages": [
            {"role": "user", "content": "Please explain how to configure security guardrails in enterprise applications."}
        ]
    }
    res = pipeline.process_inbound(payload, "req-clean-v291", "127.0.0.1")
    assert res.is_allowed
    assert res.sanitized_payload is not None
