"""Tests for the isolated, transaction-bound Solana wallet signer."""

from __future__ import annotations

import base64
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import solguard.wallet_signer as signer_module
from solguard.authorization import AuthorizationStore
from solguard.autonomous_runner import (
    ATTACKER_RECIPIENT,
    DEMO_AGENT_ID,
    DEMO_MANDATE_ID,
    DeterministicPaidResourceClient,
)
from solguard.contracts import (
    ContractValidationError,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
)
from solguard.wallet_signer import (
    MAX_SERIALIZED_TRANSACTION_BYTES,
    WALLET_SECRET_ENV,
    CanonicalTransactionCodec,
    DeterministicEd25519WalletBackend,
    IsolatedSolanaWalletSigner,
    SerializedTransactionInspector,
    SignedWalletAuthorization,
    SolanaTransactionFields,
    SolGuardAuthorizationIssuer,
    SolGuardAuthorizationVerifier,
    WalletSignerBackend,
    WalletSigningRejected,
    transaction_fields_from_request,
)
from solguard.x402 import (
    parse_payment_required_response,
)

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
RESOURCE_URL = "https://attacker.invalid/drain"


def test_exact_authorization_signs_once_and_emits_only_safe_receipt() -> None:
    context = signer_context()
    request = payment_request()
    authorization = base_authorization(request)
    envelope = context.issuer.issue(
        request=request,
        authorization=authorization,
        wallet_address=context.backend.wallet_address,
    )
    serialized = context.codec.serialize(envelope.transaction)

    parsed = SignedWalletAuthorization.from_dict(cast(dict[str, object], envelope.to_dict()))
    receipt = context.signer.sign(serialized, parsed)

    assert parsed == envelope
    assert context.backend.calls == 1
    assert receipt.wallet_address == context.backend.wallet_address
    assert receipt.request_digest == request.digest
    assert receipt.authorization_id == authorization.authorization_id
    assert receipt.signing_outcome == "SIGNED_OFFLINE_FIXTURE"
    assert serialized.decode() not in str(receipt.to_dict())
    assert WALLET_SECRET_ENV not in str(receipt.to_dict())

    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_REPLAYED"):
        context.signer.sign(serialized, envelope)
    assert context.backend.calls == 1


@pytest.mark.parametrize("serialized", [b"", b"x" * (MAX_SERIALIZED_TRANSACTION_BYTES + 1)])
def test_missing_or_invalid_serialized_transaction_never_calls_backend(
    serialized: bytes,
) -> None:
    context, envelope, _ = authorized_context()

    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
        context.signer.sign(serialized, envelope)
    assert context.backend.calls == 0


def test_missing_authorization_never_inspects_or_signs() -> None:
    context = signer_context()

    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISSING"):
        context.signer.sign(b"not-inspected", None)
    assert context.backend.calls == 0


def test_authorization_signature_or_issuer_tampering_is_rejected() -> None:
    context, envelope, serialized = authorized_context()
    invalid_signature = SignedWalletAuthorization(
        envelope.authorization,
        envelope.transaction,
        envelope.issuer_key_id,
        base64.b64encode(b"x" * 64).decode(),
    )
    unknown_issuer = SignedWalletAuthorization(
        envelope.authorization,
        envelope.transaction,
        "unknown",
        envelope.signature,
    )
    short_signature = SignedWalletAuthorization(
        envelope.authorization,
        envelope.transaction,
        envelope.issuer_key_id,
        base64.b64encode(b"short").decode(),
    )

    for candidate in (invalid_signature, unknown_issuer, short_signature):
        with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
            context.signer.sign(serialized, candidate)
    assert context.backend.calls == 0


def test_every_transaction_field_is_bound_before_signing() -> None:
    fields = transaction_fields_from_request(
        payment_request(),
        wallet_address=DeterministicEd25519WalletBackend(
            Ed25519PrivateKey.generate()
        ).wallet_address,
    )
    original = fields.to_dict()
    replacements: dict[str, JsonValue] = {
        "agent_id": "other-agent",
        "amount_atomic": "99999999",
        "expires_at": "2026-07-25T10:02:00Z",
        "network": "solana:mainnet",
        "nonce": "other-nonce",
        "recipient": "other-recipient",
        "request_digest": "sha256:other",
        "token_mint": "other-mint",
        "wallet_address": "other-wallet",
    }

    for field, replacement in replacements.items():
        context, envelope, _ = authorized_context()
        mutated = SolanaTransactionFields.from_dict(
            cast(dict[str, object], {**original, field: replacement})
        )
        serialized = context.codec.serialize(mutated)
        with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
            context.signer.sign(serialized, envelope)
        assert context.backend.calls == 0


def test_signed_mainnet_or_wrong_mint_authorization_is_still_rejected() -> None:
    for field, value in (
        ("network", "solana:mainnet"),
        ("token_mint", "wrong-mint"),
        ("request_digest", "sha256:other"),
    ):
        context, envelope, _ = authorized_context()
        transaction = SolanaTransactionFields.from_dict(
            cast(dict[str, object], {**envelope.transaction.to_dict(), field: value})
        )
        signed = sign_custom_envelope(
            issuer_key=context.issuer_key,
            authorization=envelope.authorization,
            transaction=transaction,
        )
        with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
            context.signer.sign(context.codec.serialize(transaction), signed)
        assert context.backend.calls == 0


def test_expired_authorization_and_request_expiry_are_rejected() -> None:
    context, envelope, serialized = authorized_context()
    expired_base = SigningAuthorization(
        authorization_id="expired",
        request_id=envelope.authorization.request_id,
        request_digest=envelope.authorization.request_digest,
        issued_at=NOW - timedelta(minutes=2),
        expires_at=NOW - timedelta(minutes=1),
    )
    expired = sign_custom_envelope(
        issuer_key=context.issuer_key,
        authorization=expired_base,
        transaction=envelope.transaction,
    )
    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_EXPIRED"):
        context.signer.sign(serialized, expired)

    expired_transaction = SolanaTransactionFields.from_dict(
        cast(
            dict[str, object],
            {**envelope.transaction.to_dict(), "expires_at": "2026-07-25T09:59:00Z"},
        )
    )
    expired = sign_custom_envelope(
        issuer_key=context.issuer_key,
        authorization=envelope.authorization,
        transaction=expired_transaction,
    )
    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_EXPIRED"):
        context.signer.sign(context.codec.serialize(expired_transaction), expired)
    assert context.backend.calls == 0


def test_clock_store_and_backend_failures_are_fail_closed() -> None:
    context, envelope, serialized = authorized_context(clock=lambda: datetime(2026, 7, 25))
    with pytest.raises(WalletSigningRejected, match="SYSTEM_FAILURE"):
        context.signer.sign(serialized, envelope)

    for store in (FailingStore(), InvalidStore()):
        context, envelope, serialized = authorized_context(store=store)
        with pytest.raises(WalletSigningRejected, match="SYSTEM_FAILURE"):
            context.signer.sign(serialized, envelope)
        assert context.backend.calls == 0

    for backend in (FailingBackend(), EmptyBackend()):
        context, envelope, serialized = authorized_context(backend=backend)
        with pytest.raises(WalletSigningRejected, match="SYSTEM_FAILURE"):
            context.signer.sign(serialized, envelope)


def test_invalid_inspector_output_is_fail_closed() -> None:
    class BrokenInspector:
        def inspect(self, serialized_transaction: bytes) -> SolanaTransactionFields:
            del serialized_transaction
            raise RuntimeError("parser failed")

    context, envelope, serialized = authorized_context(inspector=BrokenInspector())

    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
        context.signer.sign(serialized, envelope)
    assert context.backend.calls == 0


def test_atomic_store_allows_only_one_concurrent_signature() -> None:
    context, envelope, serialized = authorized_context()

    def attempt(_: int) -> str:
        try:
            context.signer.sign(serialized, envelope)
        except WalletSigningRejected as exc:
            return exc.reason_code.value
        return "SIGNED"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(16)))

    assert results.count("SIGNED") == 1
    assert results.count(ReasonCode.AUTHORIZATION_REPLAYED.value) == 15
    assert context.backend.calls == 1


def test_issuer_rejects_unbound_authorization() -> None:
    context = signer_context()
    request = payment_request()
    authorization = base_authorization(request)
    changed = SigningAuthorization(
        authorization.authorization_id,
        "other-request",
        authorization.request_digest,
        authorization.issued_at,
        authorization.expires_at,
    )

    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
        context.issuer.issue(
            request=request,
            authorization=changed,
            wallet_address=context.backend.wallet_address,
        )


def test_transaction_derivation_rejects_wrong_metadata_wallet_and_precision() -> None:
    request = payment_request()
    raw_metadata = request.to_dict()["metadata"]
    assert isinstance(raw_metadata, dict)
    for metadata in (
        {**raw_metadata, "network": "solana:mainnet"},
        {**raw_metadata, "asset_mint": "wrong"},
    ):
        changed = PaymentRequest.from_dict({**request.to_dict(), "metadata": metadata})
        with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
            transaction_fields_from_request(changed, wallet_address="wallet")

    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
        transaction_fields_from_request(request, wallet_address=" bad ")
    precision = PaymentRequest.from_dict({**request.to_dict(), "amount": "0.0000001"})
    with pytest.raises(WalletSigningRejected, match="AUTHORIZATION_MISMATCH"):
        transaction_fields_from_request(precision, wallet_address="wallet")


def test_serialized_contract_validation_rejects_malformed_data() -> None:
    codec = CanonicalTransactionCodec()
    for serialized in (b"not-json", b"[]"):
        with pytest.raises(ContractValidationError, match="serialized transaction is invalid"):
            codec.inspect(serialized)

    valid = transaction_fields_from_request(payment_request(), wallet_address="wallet").to_dict()
    for changed, message in (
        ({key: value for key, value in valid.items() if key != "nonce"}, "fields"),
        ({**valid, "nonce": " bad "}, "fields"),
        ({**valid, "amount_atomic": "0"}, "amount"),
    ):
        with pytest.raises(ContractValidationError, match=message):
            SolanaTransactionFields.from_dict(cast(dict[str, object], changed))


def test_wallet_authorization_deserialization_is_strict() -> None:
    _, envelope, _ = authorized_context()
    valid = envelope.to_dict()
    invalid_values = (
        {**valid, "domain": "wrong"},
        {**valid, "authorization": "wrong"},
        {**valid, "transaction": "wrong"},
        {**valid, "issuer_key_id": ""},
        {**valid, "signature": ""},
    )
    for invalid in invalid_values:
        with pytest.raises(ContractValidationError, match="wallet authorization"):
            SignedWalletAuthorization.from_dict(cast(dict[str, object], invalid))


def test_issuer_and_verifier_configuration_validation() -> None:
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(TypeError, match="wallet private_key"):
        DeterministicEd25519WalletBackend(cast(Ed25519PrivateKey, object()))
    with pytest.raises(ValueError, match="key_id"):
        SolGuardAuthorizationIssuer(key_id=" bad ", private_key=private_key)
    with pytest.raises(TypeError, match="private_key"):
        SolGuardAuthorizationIssuer(key_id="key", private_key=cast(Ed25519PrivateKey, object()))
    with pytest.raises(ValueError, match="at least one"):
        SolGuardAuthorizationVerifier({})
    with pytest.raises(ValueError, match="key_id"):
        SolGuardAuthorizationVerifier({" bad ": private_key.public_key()})
    with pytest.raises(TypeError, match="public keys"):
        SolGuardAuthorizationVerifier({"key": cast(Ed25519PublicKey, private_key)})


def test_disposable_wallet_seed_loads_only_from_external_source() -> None:
    seed = b"s" * 32
    backend = DeterministicEd25519WalletBackend.from_environment(
        {WALLET_SECRET_ENV: base64.b64encode(seed).decode()}
    )

    assert backend.wallet_address
    assert base64.b64encode(seed).decode() not in backend.wallet_address
    for environment in ({}, {WALLET_SECRET_ENV: "not-base64"}, {WALLET_SECRET_ENV: "eA=="}):
        with pytest.raises(ValueError, match=WALLET_SECRET_ENV):
            DeterministicEd25519WalletBackend.from_environment(environment)


def test_private_helpers_cover_strict_base64_and_base58_edges() -> None:
    with pytest.raises(ValueError, match="Base64"):
        signer_module._decode_base64("x" * 100, maximum_bytes=4)
    assert signer_module._base58_encode(b"\0\0") == "11"


class SignerContext:
    def __init__(
        self,
        *,
        issuer_key: Ed25519PrivateKey,
        issuer: SolGuardAuthorizationIssuer,
        backend: DeterministicEd25519WalletBackend,
        codec: CanonicalTransactionCodec,
        signer: IsolatedSolanaWalletSigner,
    ) -> None:
        self.issuer_key = issuer_key
        self.issuer = issuer
        self.backend = backend
        self.codec = codec
        self.signer = signer


def signer_context(
    *,
    clock: Callable[[], datetime] | None = None,
    store: AuthorizationStore | None = None,
    backend: WalletSignerBackend | None = None,
    inspector: SerializedTransactionInspector | None = None,
) -> SignerContext:
    issuer_key = Ed25519PrivateKey.generate()
    issuer = SolGuardAuthorizationIssuer(key_id="issuer-v1", private_key=issuer_key)
    wallet_backend = backend or DeterministicEd25519WalletBackend(Ed25519PrivateKey.generate())
    codec = CanonicalTransactionCodec()
    signer = IsolatedSolanaWalletSigner(
        verifier=SolGuardAuthorizationVerifier({"issuer-v1": issuer.public_key}),
        inspector=inspector or codec,
        backend=wallet_backend,
        authorization_store=store,
        clock=clock or (lambda: NOW),
    )
    return SignerContext(
        issuer_key=issuer_key,
        issuer=issuer,
        backend=cast(DeterministicEd25519WalletBackend, wallet_backend),
        codec=codec,
        signer=signer,
    )


def authorized_context(
    *,
    clock: Callable[[], datetime] | None = None,
    store: AuthorizationStore | None = None,
    backend: WalletSignerBackend | None = None,
    inspector: SerializedTransactionInspector | None = None,
) -> tuple[SignerContext, SignedWalletAuthorization, bytes]:
    context = signer_context(
        clock=clock,
        store=store,
        backend=backend,
        inspector=inspector,
    )
    request = payment_request()
    envelope = context.issuer.issue(
        request=request,
        authorization=base_authorization(request),
        wallet_address=context.signer._backend.wallet_address,
    )
    return context, envelope, context.codec.serialize(envelope.transaction)


def payment_request() -> PaymentRequest:
    client = DeterministicPaidResourceClient({RESOURCE_URL: ("20", ATTACKER_RECIPIENT)})
    response = client.request(RESOURCE_URL)
    requirement = parse_payment_required_response(status=response.status, headers=response.headers)
    return requirement.to_payment_request(
        agent_id=DEMO_AGENT_ID,
        mandate_id=DEMO_MANDATE_ID,
        attempt_id="wallet-signer",
        observed_at=NOW,
    )


def base_authorization(request: PaymentRequest) -> SigningAuthorization:
    return SigningAuthorization(
        authorization_id="wallet-auth-1",
        request_id=request.request_id,
        request_digest=request.digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def sign_custom_envelope(
    *,
    issuer_key: Ed25519PrivateKey,
    authorization: SigningAuthorization,
    transaction: SolanaTransactionFields,
) -> SignedWalletAuthorization:
    unsigned = SignedWalletAuthorization(
        authorization=authorization,
        transaction=transaction,
        issuer_key_id="issuer-v1",
        signature="pending",
    )
    signature = issuer_key.sign(signer_module._authorization_message(unsigned))
    return SignedWalletAuthorization(
        authorization=authorization,
        transaction=transaction,
        issuer_key_id="issuer-v1",
        signature=base64.b64encode(signature).decode(),
    )


class FailingStore:
    def consume_if_unused(self, authorization_id: str) -> bool:
        del authorization_id
        raise OSError("store offline")


class InvalidStore:
    def consume_if_unused(self, authorization_id: str) -> bool:
        del authorization_id
        return cast(bool, "not-a-boolean")


class FailingBackend:
    wallet_address = "wallet"

    def sign(self, serialized_transaction: bytes) -> str:
        del serialized_transaction
        raise OSError("signer offline")


class EmptyBackend:
    wallet_address = "wallet"

    def sign(self, serialized_transaction: bytes) -> str:
        del serialized_transaction
        return ""
