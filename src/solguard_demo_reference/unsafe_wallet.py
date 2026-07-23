"""Isolated unsafe wallet used only to demonstrate the unprotected failure mode."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from solguard.contracts import JsonObject, PaymentRequest, canonical_json, format_amount


class UnsafeReferenceFailure(RuntimeError):
    """Raised when the isolated comparison wallet cannot apply its simulated transfer."""


@dataclass(frozen=True, slots=True)
class UnsafeReferenceResult:
    """Computed evidence from one financially unprotected cryptographic signature."""

    request_digest: str
    wallet_address: str
    signature: str
    balance_before: Decimal
    balance_after: Decimal

    def to_dict(self) -> JsonObject:
        return {
            "balance_after": format_amount(self.balance_after),
            "balance_before": format_amount(self.balance_before),
            "mode": "UNSAFE_OFFLINE_REFERENCE_SIMULATION",
            "request_digest": self.request_digest,
            "signature": self.signature,
            "wallet_address": self.wallet_address,
        }


class UnsafeReferenceWallet:
    """Sign canonical fixture bytes with no SolGuard policy or authorization check."""

    def __init__(self, *, private_key: Ed25519PrivateKey, balance: Decimal) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("reference private_key must be Ed25519")
        if not balance.is_finite() or balance < 0:
            raise ValueError("reference balance must be finite and non-negative")
        self._private_key = private_key
        self._balance = balance
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._wallet_address = f"reference-ed25519:{base64.b64encode(public_key).decode('ascii')}"
        self._calls = 0

    @property
    def balance(self) -> Decimal:
        return self._balance

    @property
    def calls(self) -> int:
        return self._calls

    def execute(self, request: PaymentRequest) -> UnsafeReferenceResult:
        """Cryptographically sign and apply a transfer without financial authorization."""

        if request.amount > self._balance:
            raise UnsafeReferenceFailure("reference balance is insufficient")
        balance_before = self._balance
        balance_after = balance_before - request.amount
        transaction = canonical_json(
            {
                "amount": format_amount(request.amount),
                "asset": request.asset,
                "balance_after": format_amount(balance_after),
                "balance_before": format_amount(balance_before),
                "mode": "UNSAFE_OFFLINE_REFERENCE_SIMULATION",
                "recipient": request.recipient,
                "request_digest": request.digest,
                "wallet_address": self._wallet_address,
            }
        ).encode("utf-8")
        signature_bytes = self._private_key.sign(transaction)
        try:
            self._private_key.public_key().verify(signature_bytes, transaction)
        except InvalidSignature as exc:  # pragma: no cover - cryptography contract
            raise UnsafeReferenceFailure("reference signature verification failed") from exc
        self._balance = balance_after
        self._calls += 1
        return UnsafeReferenceResult(
            request_digest=request.digest,
            wallet_address=self._wallet_address,
            signature=base64.b64encode(signature_bytes).decode("ascii"),
            balance_before=balance_before,
            balance_after=balance_after,
        )
