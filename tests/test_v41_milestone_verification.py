import pytest
from proxy import __version__
from proxy.pipeline import SecurityPipeline


def test_v41_milestone_complete():
    assert __version__ == "4.1.0"
    pipe = SecurityPipeline()
    assert pipe.settings.ENABLE_NEURO_SYMBOLIC_SOLVER_GUARD is True
    assert pipe.settings.ENABLE_ZK_PROOF_VERIFIER_GUARD is True
    assert pipe.settings.ENABLE_HARDWARE_ENCLAVE_ATTESTATION_GUARD is True
    assert pipe.settings.ENABLE_DIFFERENTIAL_PRIVACY_BUDGET_GUARD is True
