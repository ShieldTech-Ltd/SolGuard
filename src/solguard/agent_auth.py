"""Ed25519 authentication for autonomous payment intents."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from solguard.contracts import PaymentRequest, canonical_json, format_timestamp

AGENT_SIGNATURE_DOMAIN = "solguard-agent-intent-v1"
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AgentAuthenticationError(ValueError):
    """Raised when an autonomous intent cannot be authenticated."""


@dataclass(frozen=True, slots=True)
class RegisteredAgent:
    """One agent identity key registered outside the payment request."""

    agent_id: str
    public_key: Ed25519PublicKey

    @classmethod
    def from_base64(cls, *, agent_id: str, public_key: str) -> RegisteredAgent:
        """Decode one raw Ed25519 public key from strict standard Base64."""

        if not agent_id or agent_id != agent_id.strip() or len(agent_id) > 128:
            raise ValueError("agent_id must be a non-empty trimmed identifier")
        encoded = _decode_base64(public_key, field_name="public key", maximum_bytes=32)
        if len(encoded) != 32:
            raise ValueError("public key must contain exactly 32 bytes")
        return cls(agent_id=agent_id, public_key=Ed25519PublicKey.from_public_bytes(encoded))


class AgentIdentityRegistry:
    """Verify signed payment intents against a fixed identity registry."""

    def __init__(self, identities: Mapping[str, RegisteredAgent]) -> None:
        validated: dict[str, RegisteredAgent] = {}
        for key_id, identity in identities.items():
            _validate_key_id(key_id)
            if not isinstance(identity, RegisteredAgent):
                raise TypeError("identity registry values must be RegisteredAgent instances")
            validated[key_id] = identity
        if not validated:
            raise ValueError("at least one registered agent identity is required")
        self._identities = MappingProxyType(validated)

    @property
    def agent_ids(self) -> frozenset[str]:
        """Return the agent identifiers represented by this registry."""

        return frozenset(identity.agent_id for identity in self._identities.values())

    def verify(self, request: PaymentRequest, *, key_id: str, signature: str) -> None:
        """Verify identity ownership and the domain-separated request signature."""

        try:
            _validate_key_id(key_id)
            identity = self._identities.get(key_id)
            if identity is None or identity.agent_id != request.agent_id:
                raise AgentAuthenticationError("agent authentication failed")
            raw_signature = _decode_base64(
                signature,
                field_name="signature",
                maximum_bytes=64,
            )
            if len(raw_signature) != 64:
                raise AgentAuthenticationError("agent authentication failed")
            identity.public_key.verify(
                raw_signature,
                agent_signature_message(request, key_id=key_id),
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise AgentAuthenticationError("agent authentication failed") from exc


def agent_signature_message(request: PaymentRequest, *, key_id: str) -> bytes:
    """Return the canonical domain-separated payload signed by an agent."""

    _validate_key_id(key_id)
    return canonical_json(
        {
            "agent_id": request.agent_id,
            "created_at": format_timestamp(request.created_at),
            "domain": AGENT_SIGNATURE_DOMAIN,
            "key_id": key_id,
            "nonce": request.nonce,
            "request_digest": request.digest,
        }
    ).encode("utf-8")


def sign_agent_request(
    request: PaymentRequest,
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> str:
    """Sign one payment intent without exposing private key material."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    signature = private_key.sign(agent_signature_message(request, key_id=key_id))
    return base64.b64encode(signature).decode("ascii")


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    """Export only the raw public half of an Ed25519 identity key."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    encoded = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(encoded).decode("ascii")


def _validate_key_id(key_id: str) -> None:
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ValueError("key_id is invalid")


def _decode_base64(value: str, *, field_name: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum_bytes * 2:
        raise ValueError(f"{field_name} is invalid")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} is invalid") from exc
