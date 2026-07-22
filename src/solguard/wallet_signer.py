"""Cryptographically authorized and isolated Solana-devnet wallet signer."""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from solguard.authorization import AuthorizationStore, InMemoryAuthorizationStore
from solguard.contracts import (
    ContractValidationError,
    JsonObject,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    canonical_json,
    format_timestamp,
    parse_timestamp,
)
from solguard.x402 import X402_SOLANA_DEVNET_NETWORK, X402_SOLANA_DEVNET_USDC_MINT

WALLET_AUTHORIZATION_DOMAIN = "solguard-wallet-authorization-v1"
WALLET_SECRET_ENV = "SOLGUARD_DEVNET_WALLET_SEED"
USDC_ATOMIC_FACTOR = Decimal("1000000")
MAX_SERIALIZED_TRANSACTION_BYTES = 16 * 1024


class WalletSigningRejected(RuntimeError):
    """Stable fail-closed rejection raised before or at the isolated wallet boundary."""

    def __init__(self, reason_code: ReasonCode) -> None:
        super().__init__(f"wallet signing rejected: {reason_code.value}")
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class SolanaTransactionFields:
    """Financial fields independently reconstructed from serialized transaction bytes."""

    agent_id: str
    wallet_address: str
    recipient: str
    token_mint: str
    amount_atomic: str
    network: str
    request_digest: str
    nonce: str
    expires_at: datetime

    def to_dict(self) -> JsonObject:
        return {
            "agent_id": self.agent_id,
            "amount_atomic": self.amount_atomic,
            "expires_at": format_timestamp(self.expires_at),
            "network": self.network,
            "nonce": self.nonce,
            "recipient": self.recipient,
            "request_digest": self.request_digest,
            "token_mint": self.token_mint,
            "wallet_address": self.wallet_address,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> SolanaTransactionFields:
        expected = {
            "agent_id",
            "amount_atomic",
            "expires_at",
            "network",
            "nonce",
            "recipient",
            "request_digest",
            "token_mint",
            "wallet_address",
        }
        if set(data) != expected:
            raise ContractValidationError("serialized transaction fields are invalid")
        text_fields = expected - {"expires_at"}
        values: dict[str, str] = {}
        for field in text_fields:
            value = data[field]
            if not isinstance(value, str) or not value or value != value.strip():
                raise ContractValidationError("serialized transaction fields are invalid")
            values[field] = value
        amount_atomic = values["amount_atomic"]
        if not amount_atomic.isascii() or not amount_atomic.isdigit() or int(amount_atomic) <= 0:
            raise ContractValidationError("serialized transaction amount is invalid")
        return cls(
            agent_id=values["agent_id"],
            wallet_address=values["wallet_address"],
            recipient=values["recipient"],
            token_mint=values["token_mint"],
            amount_atomic=amount_atomic,
            network=values["network"],
            request_digest=values["request_digest"],
            nonce=values["nonce"],
            expires_at=parse_timestamp(data["expires_at"], field_name="expires_at"),
        )


@dataclass(frozen=True, slots=True)
class SignedWalletAuthorization:
    """SolGuard-signed permission for one exact transaction and authorization."""

    authorization: SigningAuthorization
    transaction: SolanaTransactionFields
    issuer_key_id: str
    signature: str

    @property
    def unsigned_payload(self) -> JsonObject:
        return {
            "authorization": self.authorization.to_dict(),
            "domain": WALLET_AUTHORIZATION_DOMAIN,
            "issuer_key_id": self.issuer_key_id,
            "transaction": self.transaction.to_dict(),
        }

    def to_dict(self) -> JsonObject:
        return {**self.unsigned_payload, "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> SignedWalletAuthorization:
        if (
            set(data)
            != {
                "authorization",
                "domain",
                "issuer_key_id",
                "signature",
                "transaction",
            }
            or data.get("domain") != WALLET_AUTHORIZATION_DOMAIN
        ):
            raise ContractValidationError("wallet authorization fields are invalid")
        authorization = data["authorization"]
        transaction = data["transaction"]
        issuer_key_id = data["issuer_key_id"]
        signature = data["signature"]
        if not isinstance(authorization, dict) or not isinstance(transaction, dict):
            raise ContractValidationError("wallet authorization fields are invalid")
        if not isinstance(issuer_key_id, str) or not issuer_key_id:
            raise ContractValidationError("wallet authorization issuer is invalid")
        if not isinstance(signature, str) or not signature:
            raise ContractValidationError("wallet authorization signature is invalid")
        return cls(
            authorization=SigningAuthorization.from_dict(cast(Mapping[str, object], authorization)),
            transaction=SolanaTransactionFields.from_dict(cast(Mapping[str, object], transaction)),
            issuer_key_id=issuer_key_id,
            signature=signature,
        )


class SolGuardAuthorizationIssuer:
    """Trusted decision-side issuer; the wallet receives only its public key."""

    def __init__(self, *, key_id: str, private_key: Ed25519PrivateKey) -> None:
        if not key_id or key_id != key_id.strip() or len(key_id) > 128:
            raise ValueError("issuer key_id is invalid")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("issuer private_key must be Ed25519")
        self._key_id = key_id
        self._private_key = private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def issue(
        self,
        *,
        request: PaymentRequest,
        authorization: SigningAuthorization,
        wallet_address: str,
    ) -> SignedWalletAuthorization:
        """Sign exact request-derived transaction fields after an ALLOW decision."""

        if (
            authorization.request_id != request.request_id
            or authorization.request_digest != request.digest
        ):
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH)
        transaction = transaction_fields_from_request(request, wallet_address=wallet_address)
        unsigned = SignedWalletAuthorization(
            authorization=authorization,
            transaction=transaction,
            issuer_key_id=self._key_id,
            signature="pending",
        )
        signature = self._private_key.sign(_authorization_message(unsigned))
        return SignedWalletAuthorization(
            authorization=authorization,
            transaction=transaction,
            issuer_key_id=self._key_id,
            signature=base64.b64encode(signature).decode("ascii"),
        )


class SolGuardAuthorizationVerifier:
    """Wallet-side fixed public-key registry for SolGuard authorization issuers."""

    def __init__(self, public_keys: Mapping[str, Ed25519PublicKey]) -> None:
        if not public_keys:
            raise ValueError("at least one issuer public key is required")
        validated: dict[str, Ed25519PublicKey] = {}
        for key_id, public_key in public_keys.items():
            if not key_id or key_id != key_id.strip() or len(key_id) > 128:
                raise ValueError("issuer key_id is invalid")
            if not isinstance(public_key, Ed25519PublicKey):
                raise TypeError("issuer public keys must be Ed25519")
            validated[key_id] = public_key
        self._public_keys = validated

    def verify(self, authorization: SignedWalletAuthorization) -> None:
        """Verify the issuer and signature without revealing failure detail."""

        try:
            public_key = self._public_keys[authorization.issuer_key_id]
            signature = _decode_base64(
                authorization.signature,
                maximum_bytes=64,
            )
            if len(signature) != 64:
                raise ValueError("invalid signature length")
            public_key.verify(signature, _authorization_message(authorization))
        except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH) from exc


class SerializedTransactionInspector(Protocol):
    """Independently decode the financial fields committed by transaction bytes."""

    def inspect(self, serialized_transaction: bytes) -> SolanaTransactionFields: ...


class WalletSignerBackend(Protocol):
    """Private-key boundary unavailable to the autonomous agent."""

    @property
    def wallet_address(self) -> str: ...

    def sign(self, serialized_transaction: bytes) -> str: ...


class CanonicalTransactionCodec:
    """Explicit offline fixture codec, not a real Solana wire transaction."""

    def serialize(self, fields: SolanaTransactionFields) -> bytes:
        return canonical_json(fields.to_dict()).encode("utf-8")

    def inspect(self, serialized_transaction: bytes) -> SolanaTransactionFields:
        try:
            decoded = json.loads(serialized_transaction.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractValidationError("serialized transaction is invalid") from exc
        if not isinstance(decoded, dict):
            raise ContractValidationError("serialized transaction is invalid")
        return SolanaTransactionFields.from_dict(cast(Mapping[str, object], decoded))


class DeterministicEd25519WalletBackend:
    """Injected offline cryptographic signer with isolated key material."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("wallet private_key must be Ed25519")
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._wallet_address = _base58_encode(public_key)
        self._calls = 0

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> DeterministicEd25519WalletBackend:
        """Load a disposable raw Ed25519 seed from an external environment source."""

        source = os.environ if environment is None else environment
        value = source.get(WALLET_SECRET_ENV)
        if value is None:
            raise ValueError(f"{WALLET_SECRET_ENV} is required")
        try:
            seed = _decode_base64(value, maximum_bytes=32)
        except ValueError as exc:
            raise ValueError(f"{WALLET_SECRET_ENV} is invalid") from exc
        if len(seed) != 32:
            raise ValueError(f"{WALLET_SECRET_ENV} must contain exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def wallet_address(self) -> str:
        return self._wallet_address

    @property
    def calls(self) -> int:
        return self._calls

    def sign(self, serialized_transaction: bytes) -> str:
        self._calls += 1
        return base64.b64encode(self._private_key.sign(serialized_transaction)).decode("ascii")


@dataclass(frozen=True, slots=True)
class WalletSigningReceipt:
    """Sanitized proof emitted only after the backend signs."""

    wallet_address: str
    request_digest: str
    authorization_id: str
    transaction_signature: str
    signing_outcome: str = "SIGNED_OFFLINE_FIXTURE"

    def to_dict(self) -> JsonObject:
        return {
            "authorization_id": self.authorization_id,
            "request_digest": self.request_digest,
            "signing_outcome": self.signing_outcome,
            "transaction_signature": self.transaction_signature,
            "wallet_address": self.wallet_address,
        }


class IsolatedSolanaWalletSigner:
    """Verify, match, atomically consume, then invoke the isolated key backend."""

    def __init__(
        self,
        *,
        verifier: SolGuardAuthorizationVerifier,
        inspector: SerializedTransactionInspector,
        backend: WalletSignerBackend,
        authorization_store: AuthorizationStore | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._verifier = verifier
        self._inspector = inspector
        self._backend = backend
        self._authorization_store = authorization_store or InMemoryAuthorizationStore()
        self._clock = clock or (lambda: datetime.now(UTC))

    def sign(
        self,
        serialized_transaction: bytes,
        authorization: SignedWalletAuthorization | None,
    ) -> WalletSigningReceipt:
        """Return a signature receipt only for the exact authorized devnet transaction."""

        if authorization is None:
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISSING)
        if (
            not isinstance(serialized_transaction, bytes)
            or not serialized_transaction
            or len(serialized_transaction) > MAX_SERIALIZED_TRANSACTION_BYTES
        ):
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH)
        self._verifier.verify(authorization)
        observed_at = self._clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise WalletSigningRejected(ReasonCode.SYSTEM_FAILURE)
        if (
            observed_at >= authorization.authorization.expires_at
            or observed_at >= authorization.transaction.expires_at
        ):
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_EXPIRED)
        try:
            transaction = self._inspector.inspect(serialized_transaction)
        except Exception as exc:
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH) from exc
        if (
            transaction != authorization.transaction
            or transaction.wallet_address != self._backend.wallet_address
            or transaction.network != X402_SOLANA_DEVNET_NETWORK
            or transaction.token_mint != X402_SOLANA_DEVNET_USDC_MINT
            or authorization.authorization.request_digest != transaction.request_digest
        ):
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH)
        try:
            consumed = self._authorization_store.consume_if_unused(
                authorization.authorization.authorization_id
            )
        except Exception as exc:
            raise WalletSigningRejected(ReasonCode.SYSTEM_FAILURE) from exc
        if not isinstance(consumed, bool):
            raise WalletSigningRejected(ReasonCode.SYSTEM_FAILURE)
        if not consumed:
            raise WalletSigningRejected(ReasonCode.AUTHORIZATION_REPLAYED)
        try:
            transaction_signature = self._backend.sign(serialized_transaction)
        except Exception as exc:
            raise WalletSigningRejected(ReasonCode.SYSTEM_FAILURE) from exc
        if not transaction_signature:
            raise WalletSigningRejected(ReasonCode.SYSTEM_FAILURE)
        return WalletSigningReceipt(
            wallet_address=self._backend.wallet_address,
            request_digest=transaction.request_digest,
            authorization_id=authorization.authorization.authorization_id,
            transaction_signature=transaction_signature,
        )


def transaction_fields_from_request(
    request: PaymentRequest,
    *,
    wallet_address: str,
) -> SolanaTransactionFields:
    """Derive exact devnet transaction constraints from the canonical request."""

    network = request.metadata.get("network")
    token_mint = request.metadata.get("asset_mint")
    if network != X402_SOLANA_DEVNET_NETWORK or token_mint != X402_SOLANA_DEVNET_USDC_MINT:
        raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH)
    if not wallet_address or wallet_address != wallet_address.strip():
        raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH)
    amount_atomic = request.amount * USDC_ATOMIC_FACTOR
    if amount_atomic != amount_atomic.to_integral_value():
        raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH)
    return SolanaTransactionFields(
        agent_id=request.agent_id,
        wallet_address=wallet_address,
        recipient=request.recipient,
        token_mint=token_mint,
        amount_atomic=str(int(amount_atomic)),
        network=network,
        request_digest=request.digest,
        nonce=request.nonce,
        expires_at=request.expires_at,
    )


def _authorization_message(authorization: SignedWalletAuthorization) -> bytes:
    return canonical_json(authorization.unsigned_payload).encode("utf-8")


def _decode_base64(value: str, *, maximum_bytes: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum_bytes * 2:
        raise ValueError("Base64 value is invalid")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Base64 value is invalid") from exc


def _base58_encode(value: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    leading_zeroes = len(value) - len(value.lstrip(b"\0"))
    return "1" * leading_zeroes + encoded
