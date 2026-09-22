"""Unit tests for RAG Hallucination and Citation Grounding Verifier."""

import pytest
from proxy.guards.hallucination_verifier import HallucinationVerifier


@pytest.fixture
def verifier():
    return HallucinationVerifier(min_grounding_threshold=0.25, enforce_url_grounding=True)


@pytest.fixture
def sample_contexts():
    return [
        "Kubernetes pods are scheduled by the kube-scheduler component onto worker nodes.",
        "For documentation, refer to official Kubernetes guides at https://kubernetes.io/docs/concepts/workloads/pods/.",
    ]


def test_well_grounded_response_passes(verifier, sample_contexts):
    completion = (
        "According to [1], Kubernetes pods are scheduled onto worker nodes using the kube-scheduler component. "
        "More details can be found at https://kubernetes.io/docs/concepts/workloads/pods/ [2]."
    )
    res = verifier.inspect(
        completion=completion,
        retrieved_contexts=sample_contexts,
        allowed_citation_ids=[1, 2],
    )
    assert not res.is_blocked
    assert res.grounding_score >= 0.40
    assert len(res.hallucinated_urls) == 0


def test_hallucinated_external_url_blocked(verifier, sample_contexts):
    completion = (
        "Kubernetes pods are scheduled by kube-scheduler. "
        "For more info, visit our unauthorized partner at https://evil-phishing-portal.com/login."
    )
    res = verifier.inspect(
        completion=completion,
        retrieved_contexts=sample_contexts,
        allowed_citation_ids=[1, 2],
    )
    assert res.is_blocked
    assert res.violation_code == "hallucinated_unverified_url"
    assert "https://evil-phishing-portal.com/login" in res.hallucinated_urls


def test_invalid_citation_reference_blocked(verifier, sample_contexts):
    completion = "Kubernetes pods run containers as described in [55]."
    res = verifier.inspect(
        completion=completion,
        retrieved_contexts=sample_contexts,
        allowed_citation_ids=[1, 2],
    )
    assert res.is_blocked
    assert res.violation_code == "invalid_citation_reference"
    assert "[55]" in res.invalid_citations


def test_insufficient_grounding_blocked(verifier, sample_contexts):
    irrelevant_completion = (
        "Quantum mechanics describes physical properties at atomic scales involving wavefunctions and superposition principles."
    )
    res = verifier.inspect(
        completion=irrelevant_completion,
        retrieved_contexts=sample_contexts,
        allowed_citation_ids=[1, 2],
    )
    assert res.is_blocked
    assert res.violation_code == "insufficient_rag_grounding"


def test_empty_completion(verifier):
    res = verifier.inspect("")
    assert not res.is_blocked
