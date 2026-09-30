"""Unit tests asserting integrity and completeness of the 230 benchmark datasets."""

import json
from pathlib import Path

DATASETS_DIR = Path(__file__).resolve().parent.parent / "red_teaming" / "datasets"


def test_v3_dataset_files_exist_and_valid_json():
    required_datasets = [
        "prompt_injections.json",
        "benign_prompts.json",
        "pii_test_cases.json",
        "advanced_attacks.json",
        "database_and_ast_attacks.json",
        "nested_and_drift_attacks.json",
        "smuggling_and_command_attacks.json",
        "agentic_memory_and_exfil_attacks.json",
        "agentic_rbac_bidi_and_bombs.json",
        "agentic_shadow_and_replay_attacks.json",
        "agentic_rag_and_capability_attacks.json",
        "agentic_cost_quota_and_isolation_attacks.json",
        "agentic_plan_integrity_attacks.json",
        "cross_context_contamination_attacks.json",
        "model_inversion_attacks.json",
        "semantic_boundary_attacks.json",
    ]
    for filename in required_datasets:
        path = DATASETS_DIR / filename
        assert path.exists(), f"Missing dataset file: {filename}"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert isinstance(data, list), f"Dataset {filename} is not a JSON list"
            assert len(data) > 0, f"Dataset {filename} is empty"
            for item in data:
                assert "id" in item, f"Item missing 'id' in {filename}"
                assert any(k in item for k in ("prompt", "tool_call", "tool_calls", "output")), f"Item missing payload in {filename}"
                assert "expected_action" in item, f"Item missing 'expected_action' in {filename}"


def test_v3_datasets_total_test_count():
    plan_path = DATASETS_DIR / "agentic_plan_integrity_attacks.json"
    cross_path = DATASETS_DIR / "cross_context_contamination_attacks.json"
    inv_path = DATASETS_DIR / "model_inversion_attacks.json"
    bound_path = DATASETS_DIR / "semantic_boundary_attacks.json"

    with open(plan_path, "r", encoding="utf-8") as f:
        plan_count = len(json.load(f))
    with open(cross_path, "r", encoding="utf-8") as f:
        cross_count = len(json.load(f))
    with open(inv_path, "r", encoding="utf-8") as f:
        inv_count = len(json.load(f))
    with open(bound_path, "r", encoding="utf-8") as f:
        bound_count = len(json.load(f))

    assert plan_count == 8
    assert cross_count == 7
    assert inv_count == 8
    assert bound_count == 7
    assert (plan_count + cross_count + inv_count + bound_count) == 30
