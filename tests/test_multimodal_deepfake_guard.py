import pytest
from proxy.guards.multimodal_deepfake_guard import MultimodalDeepfakeGuard


def test_clean_multimodal_payload():
    guard = MultimodalDeepfakeGuard()
    payload = {"modality": "audio", "metadata": {"codec": "opus", "spectral_flatness": 0.2, "watermarks": []}}
    res = guard.inspect_multimodal_payload(payload)
    assert res.is_valid is True
    assert res.is_blocked is False


def test_adversarial_audio_clone_detected():
    guard = MultimodalDeepfakeGuard()
    payload = {"modality": "audio", "metadata": {"watermarks": ["deepfake_audio_cloning_signature"]}}
    res = guard.inspect_multimodal_payload(payload)
    assert res.is_blocked is True
    assert res.violation_code == "MULTIMODAL_DEEPFAKE_DETECTED"


def test_perceptual_hash_collision_blocked():
    guard = MultimodalDeepfakeGuard()
    payload = {"modality": "image", "metadata": {"phash": "adversarial_perturbation_vector_99"}}
    res = guard.inspect_multimodal_payload(payload)
    assert res.is_blocked is True
    assert "perceptual_hash_perturbation" in res.detected_artifacts
