"""Unit tests ensuring PII is redacted in prompts while preserving context (OWASP LLM06)."""

import pytest
from proxy.guards.pii_sanitizer import PIISanitizer, luhn_checksum_is_valid


@pytest.fixture
def sanitizer():
    return PIISanitizer()


def test_email_redaction(sanitizer):
    """Test that email addresses are replaced with standard redaction tokens."""
    prompt = "Please send the report to analyst.doe@cyber-firm.com before tomorrow."
    res = sanitizer.sanitize(prompt)
    assert "<REDACTED_EMAIL_1>" in res.sanitized_text
    assert "analyst.doe@cyber-firm.com" not in res.sanitized_text
    assert res.redacted_count == 1
    assert res.entities_found.get("EMAIL") == 1
    assert res.reversal_map.get("<REDACTED_EMAIL_1>") == "analyst.doe@cyber-firm.com"


def test_ssn_redaction(sanitizer):
    """Test redaction of Social Security Numbers."""
    prompt = "User account SSN is 012-34-5678, please verify."
    res = sanitizer.sanitize(prompt)
    assert "<REDACTED_SSN_1>" in res.sanitized_text
    assert "012-34-5678" not in res.sanitized_text
    assert res.entities_found.get("SSN") == 1


def test_credit_card_luhn_validation(sanitizer):
    """Test that valid Luhn cards are redacted, while invalid digit strings are preserved."""
    # Valid Visa card (Luhn passing)
    valid_card = "4532015112830366"
    assert luhn_checksum_is_valid(valid_card) is True

    # Invalid digit string (Luhn failing)
    invalid_card = "4532015112830367"
    assert luhn_checksum_is_valid(invalid_card) is False

    res_valid = sanitizer.sanitize(f"Billing card: {valid_card}")
    assert "<REDACTED_CREDIT_CARD_1>" in res_valid.sanitized_text
    assert valid_card not in res_valid.sanitized_text

    res_invalid = sanitizer.sanitize(f"Tracking code: {invalid_card}")
    assert invalid_card in res_invalid.sanitized_text


def test_api_keys_and_tokens_redaction(sanitizer):
    """Test redaction of AWS, GitHub, OpenAI keys, and JWTs."""
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    gh_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    openai_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456"
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.xyz987"

    prompt = f"Debug config: AWS={aws_key}, GH={gh_token}, OAI={openai_key}, Bearer={jwt_token}"
    res = sanitizer.sanitize(prompt)

    assert aws_key not in res.sanitized_text
    assert gh_token not in res.sanitized_text
    assert openai_key not in res.sanitized_text
    assert jwt_token not in res.sanitized_text
    assert res.entities_found.get("API_KEY") == 3
    assert res.entities_found.get("JWT_TOKEN") == 1


def test_de_anonymization_restores_original_entities(sanitizer):
    """Test round-trip de-anonymization using session reversal map."""
    prompt = "Contact alice@example.com at 555-234-5678."
    res = sanitizer.sanitize(prompt)

    # Simulated LLM response referencing the redacted tokens
    model_response = f"I have received your request and sent a confirmation message to {list(res.reversal_map.keys())[0]}."
    restored = sanitizer.de_anonymize(model_response, res.reversal_map)

    assert "alice@example.com" in restored
    assert "<REDACTED_" not in restored


def test_conversational_context_preserved(sanitizer):
    """Verify that sentence syntax and punctuation remain untouched during redaction."""
    prompt = "Hello! Please contact (415) 555-1234, or email support@security.org. Thanks!"
    res = sanitizer.sanitize(prompt)

    assert res.sanitized_text.startswith("Hello! Please contact ")
    assert ", or email " in res.sanitized_text
    assert res.sanitized_text.endswith(". Thanks!")
