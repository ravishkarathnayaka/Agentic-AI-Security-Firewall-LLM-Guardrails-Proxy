"""
Unit tests for DeserializationGuard (proxy/guards/deserialization_guard.py).
"""

import base64
import pytest
from proxy.guards.deserialization_guard import DeserializationGuard, DeserializationValidationResult


@pytest.fixture
def deserialization_guard():
    return DeserializationGuard(block_pickles=True, block_yaml_tags=True, block_java=True)


def test_benign_text_and_json_passes(deserialization_guard):
    safe_text = "Please calculate the total cost for 5 items at $20 each."
    res = deserialization_guard.inspect_text(safe_text)
    assert res.is_blocked is False

    safe_args = {"query": "SELECT name, age FROM users WHERE id = 1", "format": "json"}
    res_args = deserialization_guard.inspect_tool_arguments("db_query", safe_args)
    assert res_args.is_blocked is False


def test_pyyaml_unsafe_object_apply_blocked(deserialization_guard):
    malicious_yaml = "config: !!python/object/apply:os.system [\"id\"]"
    res = deserialization_guard.inspect_text(malicious_yaml)
    assert res.is_blocked is True
    assert res.violation_code == "unsafe_yaml_deserialization_tag"
    assert res.payload_type_detected == "yaml_gadget"


def test_base64_python_pickle_blocked(deserialization_guard):
    # Simulated pickle payload: cposix\nsystem\n(S'whoami'\ntR.
    raw_pickle = b"cposix\nsystem\np0\n(S'whoami'\np1\ntp2\nRp3."
    b64_pickle = "gASV" + base64.b64encode(raw_pickle).decode("utf-8")
    payload = f"Here is the cached state: {b64_pickle}"

    res = deserialization_guard.inspect_text(payload)
    assert res.is_blocked is True
    assert res.violation_code == "python_pickle_deserialization_detected"


def test_java_serialized_stream_blocked(deserialization_guard):
    # Standard Java serialized stream base64 prefix
    b64_java = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAU="
    payload = f"Session cookie: {b64_java}"

    res = deserialization_guard.inspect_text(payload)
    assert res.is_blocked is True
    assert res.violation_code == "java_serialized_object_detected"


def test_php_object_injection_blocked(deserialization_guard):
    php_payload = 'data = O:8:"Exploit":1:{s:4:"cmd";s:6:"whoami";}'
    res = deserialization_guard.inspect_text(php_payload)
    assert res.is_blocked is True
    assert res.violation_code == "php_object_injection"


def test_prototype_pollution_in_tool_args_blocked(deserialization_guard):
    nested_args = {
        "user_profile": {
            "settings": {
                "__proto__": {
                    "isAdmin": True
                }
            }
        }
    }
    res = deserialization_guard.inspect_tool_arguments("update_profile", nested_args)
    assert res.is_blocked is True
    assert res.violation_code == "prototype_pollution_gadget"
