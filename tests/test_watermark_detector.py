"""Unit tests for Sensitive Document Watermark and Classification Guard."""

import pytest
from proxy.guards.watermark_detector import WatermarkClassificationDetector


@pytest.fixture
def detector():
    return WatermarkClassificationDetector(block_on_match=True)


def test_public_unclassified_text_passes(detector):
    text = (
        "Welcome to our open source project. Feel free to inspect the README "
        "and contribute bug fixes or improvements via pull requests."
    )
    res = detector.inspect(text)
    assert not res.is_blocked
    assert len(res.matched_markings) == 0


def test_corporate_confidential_blocked(detector):
    text = (
        "CONFIDENTIAL // INTERNAL ONLY\n"
        "Q3 financial forecast shows an estimated revenue growth of 24%."
    )
    res = detector.inspect(text)
    assert res.is_blocked
    assert res.classification_level == "CONFIDENTIAL"
    assert res.violation_code == "corporate_confidential_marking"


def test_distribution_restriction_blocked(detector):
    text = "Here is the internal architectural RFC. Strictly DO NOT DISTRIBUTE outside the engineering group."
    res = detector.inspect(text)
    assert res.is_blocked
    assert res.classification_level == "RESTRICTED"


def test_tlp_red_blocked(detector):
    text = "Threat advisory regarding zero-day vulnerability in our auth gateway. TLP:RED"
    res = detector.inspect(text)
    assert res.is_blocked
    assert res.classification_level == "TLP_HIGH"
    assert res.violation_code == "traffic_light_protocol_restricted"


def test_legal_privilege_blocked(detector):
    text = "MEMORANDUM: ATTORNEY-CLIENT PRIVILEGED. Review of ongoing patent litigation risk."
    res = detector.inspect(text)
    assert res.is_blocked
    assert res.classification_level == "LEGAL_PRIVILEGED"


def test_empty_text(detector):
    assert not detector.inspect("").is_blocked
    assert not detector.inspect("   ").is_blocked
