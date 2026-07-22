"""Tests for autonomous-agent Ed25519 intent authentication."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from solguard.agent_auth import (
    AGENT_SIGNATURE_DOMAIN,
    AgentAuthenticationError,
    AgentIdentityRegistry,
    RegisteredAgent,
    agent_signature_message,
    public_key_base64,
    sign_agent_request,
)
from solguard.contracts import PaymentRequest
from tests.test_contracts import payment_data

KEY_ID = "research-agent-key-01"


def request(**overrides: object) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(**overrides))


def identity(
    private_key: Ed25519PrivateKey, *, agent_id: str = "research-agent-01"
) -> RegisteredAgent:
    return RegisteredAgent.from_base64(
        agent_id=agent_id,
        public_key=public_key_base64(private_key),
    )


def test_registered_agent_verifies_domain_separated_canonical_request() -> None:
    private_key = Ed25519PrivateKey.generate()
    payment = request()
    registry = AgentIdentityRegistry({KEY_ID: identity(private_key)})

    signature = sign_agent_request(payment, key_id=KEY_ID, private_key=private_key)
    registry.verify(payment, key_id=KEY_ID, signature=signature)

    assert registry.agent_ids == frozenset({payment.agent_id})
    message = agent_signature_message(payment, key_id=KEY_ID).decode()
    assert AGENT_SIGNATURE_DOMAIN in message
    assert payment.digest in message
    assert payment.nonce in message


@pytest.mark.parametrize("agent_id", ["", " padded", "x" * 129])
def test_registered_agent_rejects_invalid_agent_identifier(agent_id: str) -> None:
    with pytest.raises(ValueError, match="agent_id"):
        RegisteredAgent.from_base64(
            agent_id=agent_id,
            public_key=base64.b64encode(b"x" * 32).decode(),
        )


@pytest.mark.parametrize(
    "public_key",
    [
        "not-base64!",
        base64.b64encode(b"short").decode(),
        "A" * 65,
    ],
)
def test_registered_agent_rejects_invalid_public_key(public_key: str) -> None:
    with pytest.raises(ValueError, match="public key"):
        RegisteredAgent.from_base64(agent_id="agent", public_key=public_key)


def test_registry_requires_valid_nonempty_registered_identities() -> None:
    private_key = Ed25519PrivateKey.generate()

    with pytest.raises(ValueError, match="at least one"):
        AgentIdentityRegistry({})
    with pytest.raises(ValueError, match="key_id"):
        AgentIdentityRegistry({"bad key": identity(private_key)})
    with pytest.raises(TypeError, match="RegisteredAgent"):
        AgentIdentityRegistry({KEY_ID: object()})  # type: ignore[dict-item]


@pytest.mark.parametrize(
    ("key_id", "signature"),
    [
        ("bad key", "valid-looking"),
        ("unknown-key", base64.b64encode(b"x" * 64).decode()),
        (KEY_ID, "not-base64!"),
        (KEY_ID, base64.b64encode(b"short").decode()),
        (KEY_ID, "A" * 129),
    ],
)
def test_registry_rejects_invalid_identity_or_signature(key_id: str, signature: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    registry = AgentIdentityRegistry({KEY_ID: identity(private_key)})

    with pytest.raises(AgentAuthenticationError, match="authentication failed"):
        registry.verify(request(), key_id=key_id, signature=signature)


def test_registry_rejects_agent_mismatch_and_wrong_valid_signature() -> None:
    private_key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    registry = AgentIdentityRegistry({KEY_ID: identity(private_key)})

    wrong_agent = request(agent_id="different-agent")
    wrong_agent_signature = sign_agent_request(
        wrong_agent,
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(AgentAuthenticationError):
        registry.verify(wrong_agent, key_id=KEY_ID, signature=wrong_agent_signature)

    payment = request()
    wrong_signature = sign_agent_request(payment, key_id=KEY_ID, private_key=other_key)
    with pytest.raises(AgentAuthenticationError):
        registry.verify(payment, key_id=KEY_ID, signature=wrong_signature)


def test_signing_helpers_validate_key_and_key_identifier_types() -> None:
    payment = request()

    with pytest.raises(ValueError, match="key_id"):
        agent_signature_message(payment, key_id="bad key")
    with pytest.raises(TypeError, match="Ed25519PrivateKey"):
        sign_agent_request(payment, key_id=KEY_ID, private_key=object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="Ed25519PrivateKey"):
        public_key_base64(object())  # type: ignore[arg-type]
