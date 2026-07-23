"""Independent Solana-devnet RPC confirmation and token-balance evidence."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from solguard.contracts import JsonObject, JsonValue
from solguard.x402 import X402_SOLANA_DEVNET_NETWORK

MAX_RPC_RESPONSE_BYTES = 2 * 1024 * 1024
DEVNET_TOKEN_DISCLAIMER = "Devnet tokens have no real monetary value."


class DevnetConfirmationError(RuntimeError):
    """Raised when independent RPC evidence is missing, malformed, or inconsistent."""


class SolanaRpcTransport(Protocol):
    """Injected JSON-RPC boundary used by the confirmer."""

    def call(self, method: str, params: Sequence[JsonValue]) -> JsonValue: ...


class HttpSolanaRpcTransport:
    """Small fail-closed HTTPS JSON-RPC transport with bounded responses."""

    def __init__(self, endpoint: str, *, timeout_seconds: float = 15.0) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("RPC endpoint must be a credential-free HTTPS URL")
        if not 0 < timeout_seconds <= 60:
            raise ValueError("RPC timeout must be between 0 and 60 seconds")
        self._endpoint = endpoint
        self._timeout_seconds = timeout_seconds
        self._request_id = 0

    def call(self, method: str, params: Sequence[JsonValue]) -> JsonValue:
        if not method or method != method.strip():
            raise DevnetConfirmationError("RPC method is invalid")
        self._request_id += 1
        request_id = self._request_id
        body = json.dumps(
            {
                "id": request_id,
                "jsonrpc": "2.0",
                "method": method,
                "params": list(params),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        request = Request(
            self._endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                raw = response.read(MAX_RPC_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, OSError) as exc:
            raise DevnetConfirmationError("Solana RPC request failed") from exc
        if len(raw) > MAX_RPC_RESPONSE_BYTES:
            raise DevnetConfirmationError("Solana RPC response exceeds the local limit")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DevnetConfirmationError("Solana RPC response is invalid") from exc
        if (
            not isinstance(decoded, dict)
            or decoded.get("jsonrpc") != "2.0"
            or decoded.get("id") != request_id
            or "error" in decoded
            or "result" not in decoded
        ):
            raise DevnetConfirmationError("Solana RPC response is invalid")
        return cast(JsonValue, decoded["result"])


@dataclass(frozen=True, slots=True)
class DevnetConfirmationEvidence:
    """RPC-derived on-chain evidence for one exact SPL-token transfer."""

    transaction_signature: str
    confirmation_status: str
    slot: int
    token_mint: str
    source_owner: str
    source_token_account: str
    destination_owner: str
    destination_token_account: str
    source_delta_atomic: str
    destination_delta_atomic: str
    network: str = X402_SOLANA_DEVNET_NETWORK
    disclaimer: str = DEVNET_TOKEN_DISCLAIMER

    def to_dict(self) -> JsonObject:
        return {
            "confirmation_status": self.confirmation_status,
            "destination_delta_atomic": self.destination_delta_atomic,
            "destination_owner": self.destination_owner,
            "destination_token_account": self.destination_token_account,
            "disclaimer": self.disclaimer,
            "network": self.network,
            "slot": self.slot,
            "source_delta_atomic": self.source_delta_atomic,
            "source_owner": self.source_owner,
            "source_token_account": self.source_token_account,
            "token_mint": self.token_mint,
            "transaction_signature": self.transaction_signature,
        }


@dataclass(frozen=True, slots=True)
class _TokenBalance:
    account_index: int
    owner: str
    amount: int


class SolanaDevnetConfirmer:
    """Require finalized/confirmed status and exact RPC-derived token deltas."""

    def __init__(self, transport: SolanaRpcTransport) -> None:
        self._transport = transport

    def confirm(
        self,
        *,
        transaction_signature: str,
        expected_mint: str,
        expected_source_owner: str,
        expected_destination_owner: str,
        expected_amount_atomic: str,
    ) -> DevnetConfirmationEvidence:
        """Independently confirm one exact devnet token transfer through RPC."""

        if (
            not transaction_signature
            or transaction_signature != transaction_signature.strip()
            or len(transaction_signature) > 128
            or not expected_amount_atomic.isascii()
            or not expected_amount_atomic.isdigit()
            or int(expected_amount_atomic) <= 0
        ):
            raise DevnetConfirmationError("confirmation request is invalid")
        status_result = self._transport.call(
            "getSignatureStatuses",
            [
                [transaction_signature],
                {"searchTransactionHistory": True},
            ],
        )
        status, slot = _confirmed_status(status_result)
        transaction_result = self._transport.call(
            "getTransaction",
            [
                transaction_signature,
                {
                    "commitment": "confirmed",
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )
        transaction, transaction_slot = _transaction_payload(transaction_result)
        if transaction_slot != slot:
            raise DevnetConfirmationError("RPC confirmation slots do not match")
        account_keys = _account_keys(transaction)
        meta = transaction["meta"]
        assert isinstance(meta, dict)
        pre = _token_balances(meta.get("preTokenBalances"), expected_mint=expected_mint)
        post = _token_balances(meta.get("postTokenBalances"), expected_mint=expected_mint)
        amount = int(expected_amount_atomic)
        source = _matching_delta(
            pre,
            post,
            owner=expected_source_owner,
            expected_delta=-amount,
        )
        destination = _matching_delta(
            pre,
            post,
            owner=expected_destination_owner,
            expected_delta=amount,
        )
        return DevnetConfirmationEvidence(
            transaction_signature=transaction_signature,
            confirmation_status=status,
            slot=slot,
            token_mint=expected_mint,
            source_owner=expected_source_owner,
            source_token_account=_account_key(account_keys, source),
            destination_owner=expected_destination_owner,
            destination_token_account=_account_key(account_keys, destination),
            source_delta_atomic=str(-amount),
            destination_delta_atomic=str(amount),
        )


def _confirmed_status(value: JsonValue) -> tuple[str, int]:
    if not isinstance(value, dict):
        raise DevnetConfirmationError("signature status response is invalid")
    entries = value.get("value")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise DevnetConfirmationError("signature status response is invalid")
    entry = entries[0]
    status = entry.get("confirmationStatus")
    slot = entry.get("slot")
    if (
        entry.get("err") is not None
        or status not in {"confirmed", "finalized"}
        or not isinstance(slot, int)
        or isinstance(slot, bool)
        or slot <= 0
    ):
        raise DevnetConfirmationError("transaction is not confirmed successfully")
    return cast(str, status), slot


def _transaction_payload(value: JsonValue) -> tuple[dict[str, JsonValue], int]:
    if not isinstance(value, dict):
        raise DevnetConfirmationError("transaction response is invalid")
    slot = value.get("slot")
    meta = value.get("meta")
    transaction = value.get("transaction")
    if (
        not isinstance(slot, int)
        or isinstance(slot, bool)
        or slot <= 0
        or not isinstance(meta, dict)
        or meta.get("err") is not None
        or not isinstance(transaction, dict)
        or not isinstance(transaction.get("message"), dict)
    ):
        raise DevnetConfirmationError("transaction response is invalid")
    return {"meta": meta, "transaction": transaction}, slot


def _account_keys(transaction: Mapping[str, JsonValue]) -> list[str]:
    raw_transaction = transaction["transaction"]
    assert isinstance(raw_transaction, dict)
    message = raw_transaction["message"]
    assert isinstance(message, dict)
    raw_keys = message.get("accountKeys")
    if not isinstance(raw_keys, list):
        raise DevnetConfirmationError("transaction account keys are invalid")
    keys: list[str] = []
    for entry in raw_keys:
        key = entry.get("pubkey") if isinstance(entry, dict) else entry
        if not isinstance(key, str) or not key:
            raise DevnetConfirmationError("transaction account keys are invalid")
        keys.append(key)
    return keys


def _token_balances(value: JsonValue | None, *, expected_mint: str) -> dict[int, _TokenBalance]:
    if not isinstance(value, list):
        raise DevnetConfirmationError("transaction token balances are invalid")
    result: dict[int, _TokenBalance] = {}
    for entry in value:
        if not isinstance(entry, dict) or entry.get("mint") != expected_mint:
            continue
        index = entry.get("accountIndex")
        owner = entry.get("owner")
        ui_amount = entry.get("uiTokenAmount")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            or index in result
            or not isinstance(owner, str)
            or not owner
            or not isinstance(ui_amount, dict)
            or ui_amount.get("decimals") != 6
        ):
            raise DevnetConfirmationError("transaction token balances are invalid")
        amount = ui_amount.get("amount")
        if not isinstance(amount, str) or not amount.isascii() or not amount.isdigit():
            raise DevnetConfirmationError("transaction token balances are invalid")
        result[index] = _TokenBalance(index, owner, int(amount))
    if not result:
        raise DevnetConfirmationError("expected token mint is absent from transaction")
    return result


def _matching_delta(
    pre: Mapping[int, _TokenBalance],
    post: Mapping[int, _TokenBalance],
    *,
    owner: str,
    expected_delta: int,
) -> int:
    matches: list[int] = []
    for index in pre.keys() | post.keys():
        before = pre.get(index)
        after = post.get(index)
        observed_owner = (
            after.owner if after is not None else before.owner if before is not None else ""
        )
        if before is not None and after is not None and before.owner != after.owner:
            raise DevnetConfirmationError("token-account ownership changed unexpectedly")
        if observed_owner != owner:
            continue
        delta = (after.amount if after is not None else 0) - (
            before.amount if before is not None else 0
        )
        if delta == expected_delta:
            matches.append(index)
    if len(matches) != 1:
        raise DevnetConfirmationError("expected token balance delta was not observed exactly once")
    return matches[0]


def _account_key(keys: Sequence[str], index: int) -> str:
    try:
        return keys[index]
    except IndexError as exc:
        raise DevnetConfirmationError("token balance references an unknown account") from exc
