import json
import os
import pytest


def test_v42_benchmark_coverage():
    runner_file = "red_teaming/runner.py"
    assert os.path.exists(runner_file)
    with open(runner_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "512-case benchmark support" in content
