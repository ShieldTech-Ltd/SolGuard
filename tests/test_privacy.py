"""Tests for bounded, deterministic payment metadata sanitization."""

from __future__ import annotations

from copy import deepcopy

import pytest

from solguard.contracts import PaymentRequest
from solguard.privacy import MetadataSanitizer, RedactionCategory, SanitizationLimits
from tests.test_contracts import payment_data


def request_with_metadata(metadata: dict[str, object]) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(metadata=metadata))


def test_sanitizes_supported_sensitive_values_without_mutating_request() -> None:
    metadata: dict[str, object] = {
        "contact": "alice@example.com",
        "authorization": "Bearer abcdefghijklmnop",
        "api_key": "ghp_abcdefghijklmnop",
        "session_id": "session-value-12345",
        "card": "4111 1111 1111 1111",
        "safe": "weather request",
    }
    original = deepcopy(metadata)
    payment = request_with_metadata(metadata)

    result = MetadataSanitizer().sanitize_payment(payment)

    assert result.data == {
        "api_key": "[REDACTED:API_KEY]",
        "authorization": "[REDACTED:BEARER_TOKEN]",
        "card": "[REDACTED:CARD_LIKE]",
        "contact": "[REDACTED:EMAIL]",
        "safe": "weather request",
        "session_id": "[REDACTED:SESSION_ID]",
    }
    assert result.redaction_counts == {
        RedactionCategory.API_KEY: 1,
        RedactionCategory.BEARER_TOKEN: 1,
        RedactionCategory.CARD_LIKE: 1,
        RedactionCategory.EMAIL: 1,
        RedactionCategory.SESSION_ID: 1,
    }
    assert result.limits_applied == ()
    assert metadata == original
    assert payment.metadata == original


def test_redacts_multiple_free_text_patterns_and_reports_counts() -> None:
    metadata = {
        "message": (
            "email first@example.com and second@example.org; "
            "token sk-abcdefghijklmnop; session_token=abcdefghijk"
        )
    }

    result = MetadataSanitizer().sanitize(metadata)

    rendered = str(result.to_dict())
    assert "first@example.com" not in rendered
    assert "second@example.org" not in rendered
    assert "sk-abcdefghijklmnop" not in rendered
    assert "abcdefghijk" not in rendered
    assert result.redaction_counts[RedactionCategory.EMAIL] == 2
    assert result.redaction_counts[RedactionCategory.API_KEY] == 1
    assert result.redaction_counts[RedactionCategory.SESSION_ID] == 1


@pytest.mark.parametrize(
    "field",
    ["API-Key", "apiKey", "access_token", "AUTH_TOKEN", "password", "private_key"],
)
def test_sensitive_field_name_redacts_entire_value(field: str) -> None:
    result = MetadataSanitizer().sanitize({field: {"nested": "must-not-leak"}})

    assert result.data[field] == "[REDACTED:API_KEY]"
    assert "must-not-leak" not in str(result.to_dict())


@pytest.mark.parametrize("field", ["cookie", "Session-Token", "set_cookie"])
def test_session_field_name_redacts_entire_value(field: str) -> None:
    result = MetadataSanitizer().sanitize({field: "abcdefghijk"})

    assert result.data[field] == "[REDACTED:SESSION_ID]"


def test_authorization_field_is_reported_as_bearer_token() -> None:
    result = MetadataSanitizer().sanitize({"Authorization": "Basic abcdefghijk"})

    assert result.data["Authorization"] == "[REDACTED:BEARER_TOKEN]"


def test_non_luhn_digit_sequence_is_not_claimed_as_card_data() -> None:
    value = "reference 1234 5678 9012 3456"

    result = MetadataSanitizer().sanitize({"reference": value})

    assert result.data["reference"] == value
    assert RedactionCategory.CARD_LIKE not in result.redaction_counts


def test_sensitive_value_inside_list_is_redacted() -> None:
    result = MetadataSanitizer().sanitize(
        {"items": ["safe", "Bearer abcdefghijklmnop", {"contact": "a@example.com"}]}
    )

    assert result.data == {
        "items": [
            "safe",
            "[REDACTED:BEARER_TOKEN]",
            {"contact": "[REDACTED:EMAIL]"},
        ]
    }


def test_sensitive_key_text_is_replaced_without_leaking_key() -> None:
    result = MetadataSanitizer().sanitize({"alice@example.com": "safe"})

    assert result.data == {"_redacted_key_0": "safe"}
    assert "alice@example.com" not in str(result.to_dict())


def test_duplicate_keys_after_sanitization_remain_deterministic() -> None:
    result = MetadataSanitizer().sanitize({"a@example.com": "first", "b@example.com": "second"})

    assert result.data == {
        "_redacted_key_0": "first",
        "_redacted_key_1": "second",
    }


def test_depth_is_bounded() -> None:
    sanitizer = MetadataSanitizer(SanitizationLimits(max_depth=2))

    result = sanitizer.sanitize({"one": {"two": {"secret": "value"}}})

    assert result.data == {"one": {"two": {"_redacted": "DEPTH_LIMIT"}}}
    assert result.limits_applied == ("DEPTH",)
    assert "value" not in str(result.to_dict())


def test_list_depth_is_bounded() -> None:
    sanitizer = MetadataSanitizer(SanitizationLimits(max_depth=2))

    result = sanitizer.sanitize({"one": [["must-not-leak"]]})

    assert result.data == {"one": ["[REDACTED:DEPTH_LIMIT]"]}
    assert result.limits_applied == ("DEPTH",)


def test_collection_size_is_bounded_for_objects_and_lists() -> None:
    sanitizer = MetadataSanitizer(SanitizationLimits(max_collection_items=2))

    result = sanitizer.sanitize(
        {"a": 1, "b": 2, "c": "must-not-leak", "items": [1, 2, "must-not-leak"]}
    )

    assert result.data == {"a": 1, "b": 2}
    assert result.limits_applied == ("COLLECTION_ITEMS",)
    assert "must-not-leak" not in str(result.to_dict())


def test_list_collection_size_is_bounded() -> None:
    sanitizer = MetadataSanitizer(SanitizationLimits(max_collection_items=2))

    result = sanitizer.sanitize({"items": [1, 2, "must-not-leak"]})

    assert result.data == {"items": [1, 2]}
    assert result.limits_applied == ("COLLECTION_ITEMS",)


def test_string_length_is_bounded_after_redaction() -> None:
    sanitizer = MetadataSanitizer(SanitizationLimits(max_string_length=12))

    result = sanitizer.sanitize({"message": "safe-prefix alice@example.com trailing"})

    assert result.data == {"message": "safe-prefix [TRUNCATED]"}
    assert result.limits_applied == ("STRING_LENGTH",)
    assert "alice@example.com" not in str(result.to_dict())


def test_total_metadata_size_replaces_entire_safe_copy() -> None:
    sanitizer = MetadataSanitizer(SanitizationLimits(max_metadata_bytes=20))

    result = sanitizer.sanitize({"message": "a value larger than twenty bytes"})

    assert result.data == {"_redacted": "METADATA_SIZE_LIMIT"}
    assert result.limits_applied == ("METADATA_SIZE",)


def test_long_and_colliding_keys_are_bounded_deterministically() -> None:
    sanitizer = MetadataSanitizer(SanitizationLimits(max_string_length=12))

    result = sanitizer.sanitize({"abcdefghijkl-first": 1, "abcdefghijkl-second": 2})

    assert result.data == {"abcdefghijkl": 1, "abcdefghij_1": 2}
    assert result.limits_applied == ("STRING_LENGTH",)


def test_luhn_rejects_candidate_outside_supported_length() -> None:
    assert MetadataSanitizer._passes_luhn("123") is False


def test_empty_safe_metadata_has_no_redaction_evidence() -> None:
    result = MetadataSanitizer().sanitize({})

    assert result.to_dict() == {
        "data": {},
        "limits_applied": [],
        "redaction_counts": {},
    }


def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        SanitizationLimits(max_depth=0)
    with pytest.raises(ValueError, match="positive"):
        SanitizationLimits(max_collection_items=0)
    with pytest.raises(ValueError, match="positive"):
        SanitizationLimits(max_string_length=0)
    with pytest.raises(ValueError, match="positive"):
        SanitizationLimits(max_metadata_bytes=0)
