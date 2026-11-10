"""
backend/tests/test_pii.py – unit tests for backend.pii

Covers:
  - Bearer token masking
  - E-mail address masking
  - Credit card number masking (with/without separators)
  - Phone number masking (various formats)
  - Combined payload with multiple PII types
  - Non-PII text is preserved
  - mask_record_bodies masks req_body and resp_body
  - mask_alert masks explanation field
  - JSON payload masking (embedded in string)
  - card_last4 (4-digit numbers) are NOT masked by card-number pattern
"""
from __future__ import annotations

import json

import pytest

from backend.pii import mask, mask_alert, mask_record_bodies


# ---------------------------------------------------------------------------
# Token masking
# ---------------------------------------------------------------------------

class TestTokenMasking:

    def test_token_alice_masked(self):
        result = mask("Bearer token-alice")
        assert "token-alice" not in result
        assert "[TOKEN-MASKED]" in result

    def test_token_bob_masked(self):
        assert "[TOKEN-MASKED]" in mask("token-bob")

    def test_token_in_json_string(self):
        payload = json.dumps({"Authorization": "Bearer token-carol"})
        result = mask(payload)
        assert "token-carol" not in result
        assert "[TOKEN-MASKED]" in result

    def test_non_token_bearer_not_masked(self):
        # Only project tokens (token-<name>) should be masked;
        # a random word after Bearer is not a known token format.
        # The pattern specifically targets "token-<alphanum>"
        result = mask("Bearer somethingelse123")
        # "somethingelse123" does not start with "token-" so not masked
        assert "somethingelse123" in result


# ---------------------------------------------------------------------------
# E-mail masking
# ---------------------------------------------------------------------------

class TestEmailMasking:

    def test_simple_email_masked(self):
        assert "[EMAIL-MASKED]" in mask("alice@example.com")

    def test_email_in_json_body_masked(self):
        payload = '{"email": "bob@example.com", "name": "Bob"}'
        result = mask(payload)
        assert "bob@example.com" not in result
        assert "[EMAIL-MASKED]" in result

    def test_email_with_plus_masked(self):
        assert "[EMAIL-MASKED]" in mask("user+tag@domain.org")

    def test_multiple_emails_masked(self):
        text = "alice@example.com and bob@example.com"
        result = mask(text)
        assert "alice@example.com" not in result
        assert "bob@example.com" not in result
        assert result.count("[EMAIL-MASKED]") == 2

    def test_non_email_text_preserved(self):
        result = mask("hello world no email here")
        assert result == "hello world no email here"


# ---------------------------------------------------------------------------
# Card number masking
# ---------------------------------------------------------------------------

class TestCardMasking:

    def test_16_digit_card_masked(self):
        assert "[CARD-MASKED]" in mask("4111111111111111")

    def test_card_with_spaces_masked(self):
        assert "[CARD-MASKED]" in mask("4111 1111 1111 1111")

    def test_card_with_hyphens_masked(self):
        assert "[CARD-MASKED]" in mask("4111-1111-1111-1111")

    def test_card_in_json_body(self):
        payload = '{"card_number": "5500005555555559", "amount": 100}'
        result = mask(payload)
        assert "5500005555555559" not in result
        assert "[CARD-MASKED]" in result

    def test_four_digit_number_not_masked(self):
        """card_last4 (4-digit number) should NOT be treated as a full card."""
        result = mask("card_last4: 4242")
        # 4-digit number does not match 16-digit card pattern
        assert "4242" in result
        assert "[CARD-MASKED]" not in result


# ---------------------------------------------------------------------------
# Phone number masking
# ---------------------------------------------------------------------------

class TestPhoneMasking:

    def test_us_phone_hyphenated(self):
        assert "[PHONE-MASKED]" in mask("555-123-4567")

    def test_us_phone_spaced(self):
        assert "[PHONE-MASKED]" in mask("(555) 123-4567")

    def test_international_phone(self):
        assert "[PHONE-MASKED]" in mask("+1 555-123-4567")

    def test_non_phone_number_preserved(self):
        # Short numbers like "101" should not be matched as phone numbers
        result = mask("order id 101")
        assert "[PHONE-MASKED]" not in result


# ---------------------------------------------------------------------------
# Combined payload
# ---------------------------------------------------------------------------

class TestCombinedMasking:

    def test_all_pii_types_in_one_payload(self):
        payload = (
            '{"email":"alice@example.com",'
            '"token":"token-alice",'
            '"phone":"555-123-4567",'
            '"card":"4111111111111111"}'
        )
        result = mask(payload)
        assert "alice@example.com" not in result
        assert "token-alice" not in result
        assert "4111111111111111" not in result
        assert "[EMAIL-MASKED]" in result
        assert "[TOKEN-MASKED]" in result
        assert "[CARD-MASKED]" in result

    def test_non_pii_text_fully_preserved(self):
        text = "Normal business data: order 101, item Laptop, amount 55000"
        result = mask(text)
        assert result == text


# ---------------------------------------------------------------------------
# mask_record_bodies
# ---------------------------------------------------------------------------

class TestMaskRecordBodies:

    def test_masks_resp_body(self):
        record = {
            "ts": "2026-11-09T05:00:00+00:00",
            "method": "GET",
            "path": "/api/v1/users/me",
            "req_body": "",
            "resp_body": '{"email":"alice@example.com","id":1}',
        }
        result = mask_record_bodies(record)
        assert "alice@example.com" not in result["resp_body"]
        assert "[EMAIL-MASKED]" in result["resp_body"]

    def test_masks_req_body(self):
        record = {
            "req_body": '{"username":"alice","password":"alice123","email":"alice@example.com"}',
            "resp_body": '{"token":"token-alice"}',
        }
        result = mask_record_bodies(record)
        assert "alice@example.com" not in result["req_body"]
        assert "token-alice" not in result["resp_body"]

    def test_original_dict_not_mutated(self):
        record = {"req_body": "alice@example.com", "resp_body": "clean"}
        original_req = record["req_body"]
        mask_record_bodies(record)
        assert record["req_body"] == original_req  # original unchanged

    def test_non_string_fields_ignored(self):
        """Non-string values in req_body/resp_body don't crash."""
        record = {"req_body": None, "resp_body": None}
        result = mask_record_bodies(record)
        # None values remain None (or unchanged)
        assert result is not record  # shallow copy made


# ---------------------------------------------------------------------------
# mask_alert
# ---------------------------------------------------------------------------

class TestMaskAlert:

    def test_masks_explanation_field(self):
        alert = {
            "id": "abc",
            "explanation": "User alice@example.com accessed object 201",
            "type": "BOLA",
        }
        result = mask_alert(alert)
        assert "alice@example.com" not in result["explanation"]
        assert "[EMAIL-MASKED]" in result["explanation"]

    def test_other_fields_untouched(self):
        alert = {"id": "abc", "type": "BOLA", "explanation": "clean"}
        result = mask_alert(alert)
        assert result["id"] == "abc"
        assert result["type"] == "BOLA"

    def test_original_not_mutated(self):
        alert = {"explanation": "alice@example.com", "id": "x"}
        original = alert["explanation"]
        mask_alert(alert)
        assert alert["explanation"] == original

