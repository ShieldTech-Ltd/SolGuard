"""Tests for independent Solana-devnet RPC confirmation evidence."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import cast
from urllib.error import URLError

import pytest

import solguard.devnet_rpc as rpc_module
from solguard.contracts import JsonValue
from solguard.devnet_rpc import (
    DEVNET_TOKEN_DISCLAIMER,
    MAX_RPC_RESPONSE_BYTES,
    DevnetConfirmationError,
    HttpSolanaRpcTransport,
    SolanaDevnetConfirmer,
)
from solguard.x402 import X402_SOLANA_DEVNET_NETWORK, X402_SOLANA_DEVNET_USDC_MINT

SIGNATURE = "devnet-signature"
SOURCE_OWNER = "source-owner"
DESTINATION_OWNER = "destination-owner"
SOURCE_ACCOUNT = "source-token-account"
DESTINATION_ACCOUNT = "destination-token-account"


def test_rpc_confirmation_derives_exact_on_chain_evidence() -> None:
    transport = FixtureTransport(status_fixture(), transaction_fixture())
    evidence = confirmer(transport).confirm(
        transaction_signature=SIGNATURE,
        expected_mint=X402_SOLANA_DEVNET_USDC_MINT,
        expected_source_owner=SOURCE_OWNER,
        expected_destination_owner=DESTINATION_OWNER,
        expected_amount_atomic="100",
    )

    assert transport.methods == ["getSignatureStatuses", "getTransaction"]
    assert evidence.transaction_signature == SIGNATURE
    assert evidence.confirmation_status == "confirmed"
    assert evidence.slot == 123
    assert evidence.network == X402_SOLANA_DEVNET_NETWORK
    assert evidence.token_mint == X402_SOLANA_DEVNET_USDC_MINT
    assert evidence.source_token_account == SOURCE_ACCOUNT
    assert evidence.destination_token_account == DESTINATION_ACCOUNT
    assert evidence.source_delta_atomic == "-100"
    assert evidence.destination_delta_atomic == "100"
    assert evidence.disclaimer == DEVNET_TOKEN_DISCLAIMER
    assert evidence.to_dict()["disclaimer"] == DEVNET_TOKEN_DISCLAIMER


@pytest.mark.parametrize(
    ("signature", "amount"),
    [("", "100"), (" bad ", "100"), ("x" * 129, "100"), (SIGNATURE, "0")],
)
def test_confirmation_request_validation(signature: str, amount: str) -> None:
    transport = FixtureTransport(status_fixture(), transaction_fixture())

    with pytest.raises(DevnetConfirmationError, match="confirmation request"):
        confirmer(transport).confirm(
            transaction_signature=signature,
            expected_mint=X402_SOLANA_DEVNET_USDC_MINT,
            expected_source_owner=SOURCE_OWNER,
            expected_destination_owner=DESTINATION_OWNER,
            expected_amount_atomic=amount,
        )
    assert transport.methods == []


@pytest.mark.parametrize(
    "status",
    [
        None,
        {},
        {"value": []},
        {"value": [None]},
        {"value": [{"err": "failure", "confirmationStatus": "confirmed", "slot": 123}]},
        {"value": [{"err": None, "confirmationStatus": "processed", "slot": 123}]},
        {"value": [{"err": None, "confirmationStatus": "confirmed", "slot": 0}]},
        {"value": [{"err": None, "confirmationStatus": "confirmed", "slot": True}]},
    ],
)
def test_unconfirmed_or_malformed_status_fails_closed(status: JsonValue) -> None:
    with pytest.raises(DevnetConfirmationError):
        confirm_with(status, transaction_fixture())


def test_finalized_status_is_accepted() -> None:
    status = status_fixture()
    cast(dict[str, JsonValue], cast(list[JsonValue], status["value"])[0])["confirmationStatus"] = (
        "finalized"
    )

    evidence = confirm_with(status, transaction_fixture())

    assert evidence.confirmation_status == "finalized"


@pytest.mark.parametrize(
    "transaction",
    [
        None,
        {},
        {"slot": 0, "meta": {}, "transaction": {}},
        {"slot": True, "meta": {}, "transaction": {}},
        {"slot": 123, "meta": {"err": "failure"}, "transaction": {"message": {}}},
        {"slot": 123, "meta": {}, "transaction": {}},
    ],
)
def test_malformed_or_failed_transaction_fails_closed(transaction: JsonValue) -> None:
    with pytest.raises(DevnetConfirmationError, match="transaction response"):
        confirm_with(status_fixture(), transaction)


def test_confirmation_slots_must_match() -> None:
    transaction = transaction_fixture()
    transaction["slot"] = 124

    with pytest.raises(DevnetConfirmationError, match="slots do not match"):
        confirm_with(status_fixture(), transaction)


@pytest.mark.parametrize(
    "account_keys",
    [None, [None, DESTINATION_ACCOUNT], [{"pubkey": ""}, DESTINATION_ACCOUNT]],
)
def test_account_keys_must_be_complete(account_keys: JsonValue) -> None:
    transaction = transaction_fixture()
    message(transaction)["accountKeys"] = account_keys

    with pytest.raises(DevnetConfirmationError, match="account keys"):
        confirm_with(status_fixture(), transaction)


@pytest.mark.parametrize(
    ("side", "balances"),
    [
        ("preTokenBalances", None),
        ("postTokenBalances", None),
        ("preTokenBalances", [None]),
        ("preTokenBalances", []),
    ],
)
def test_token_balances_are_required(side: str, balances: JsonValue) -> None:
    transaction = transaction_fixture()
    meta(transaction)[side] = balances

    with pytest.raises(DevnetConfirmationError, match=r"token balances|token mint"):
        confirm_with(status_fixture(), transaction)


@pytest.mark.parametrize(
    "change",
    [
        {"accountIndex": True},
        {"accountIndex": -1},
        {"owner": ""},
        {"uiTokenAmount": None},
        {"uiTokenAmount": {"amount": "1000", "decimals": 9}},
        {"uiTokenAmount": {"amount": "bad", "decimals": 6}},
    ],
)
def test_each_matching_token_balance_is_strict(change: dict[str, JsonValue]) -> None:
    transaction = transaction_fixture()
    entries = cast(list[JsonValue], meta(transaction)["preTokenBalances"])
    first = cast(dict[str, JsonValue], entries[0])
    first.update(change)

    with pytest.raises(DevnetConfirmationError, match="token balances"):
        confirm_with(status_fixture(), transaction)


def test_duplicate_account_index_is_rejected() -> None:
    transaction = transaction_fixture()
    entries = cast(list[JsonValue], meta(transaction)["preTokenBalances"])
    entries.append(deepcopy(entries[0]))

    with pytest.raises(DevnetConfirmationError, match="token balances"):
        confirm_with(status_fixture(), transaction)


def test_owner_change_delta_mismatch_and_unknown_account_fail_closed() -> None:
    changed_owner = transaction_fixture()
    post = cast(list[JsonValue], meta(changed_owner)["postTokenBalances"])
    cast(dict[str, JsonValue], post[0])["owner"] = "changed-owner"
    with pytest.raises(DevnetConfirmationError, match="ownership changed"):
        confirm_with(status_fixture(), changed_owner)

    wrong_delta = transaction_fixture()
    post = cast(list[JsonValue], meta(wrong_delta)["postTokenBalances"])
    cast(dict[str, JsonValue], cast(dict[str, JsonValue], post[0])["uiTokenAmount"])["amount"] = (
        "901"
    )
    with pytest.raises(DevnetConfirmationError, match="delta was not observed"):
        confirm_with(status_fixture(), wrong_delta)

    unknown_account = transaction_fixture()
    pre = cast(list[JsonValue], meta(unknown_account)["preTokenBalances"])
    post = cast(list[JsonValue], meta(unknown_account)["postTokenBalances"])
    cast(dict[str, JsonValue], pre[1])["accountIndex"] = 9
    cast(dict[str, JsonValue], post[1])["accountIndex"] = 9
    with pytest.raises(DevnetConfirmationError, match="unknown account"):
        confirm_with(status_fixture(), unknown_account)


def test_http_transport_validates_endpoint_timeout_and_method() -> None:
    for endpoint in (
        "http://rpc.example.test",
        "https://user:pass@rpc.example.test",
        "https://rpc.example.test?a=1",
    ):
        with pytest.raises(ValueError, match="credential-free HTTPS"):
            HttpSolanaRpcTransport(endpoint)
    with pytest.raises(ValueError, match="timeout"):
        HttpSolanaRpcTransport("https://rpc.example.test", timeout_seconds=0)
    transport = HttpSolanaRpcTransport("https://rpc.example.test")
    with pytest.raises(DevnetConfirmationError, match="method"):
        transport.call(" bad ", [])


def test_http_transport_posts_json_rpc_and_validates_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [
        FakeHttpResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode()),
        FakeHttpResponse(b"not-json"),
        FakeHttpResponse(json.dumps({"jsonrpc": "2.0", "id": 3, "error": {}}).encode()),
        FakeHttpResponse(b"x" * (MAX_RPC_RESPONSE_BYTES + 1)),
    ]
    captured: list[object] = []

    def fake_urlopen(request: object, *, timeout: float) -> FakeHttpResponse:
        captured.extend((request, timeout))
        return responses.pop(0)

    monkeypatch.setattr(rpc_module, "urlopen", fake_urlopen)
    transport = HttpSolanaRpcTransport("https://rpc.example.test", timeout_seconds=5)

    assert transport.call("method", [{"value": True}]) == {"ok": True}
    assert captured[1] == 5
    for _ in range(3):
        with pytest.raises(DevnetConfirmationError):
            transport.call("method", [])


def test_http_transport_wraps_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rpc_module,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("offline")),
    )

    with pytest.raises(DevnetConfirmationError, match="request failed"):
        HttpSolanaRpcTransport("https://rpc.example.test").call("method", [])


class FixtureTransport:
    def __init__(self, status: JsonValue, transaction: JsonValue) -> None:
        self._responses = {
            "getSignatureStatuses": status,
            "getTransaction": transaction,
        }
        self.methods: list[str] = []

    def call(self, method: str, params: object) -> JsonValue:
        assert params
        self.methods.append(method)
        return self._responses[method]


class FakeHttpResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self._body[:size]


def confirmer(transport: FixtureTransport) -> SolanaDevnetConfirmer:
    return SolanaDevnetConfirmer(transport)


def confirm_with(
    status: JsonValue, transaction: JsonValue
) -> rpc_module.DevnetConfirmationEvidence:
    return confirmer(FixtureTransport(status, transaction)).confirm(
        transaction_signature=SIGNATURE,
        expected_mint=X402_SOLANA_DEVNET_USDC_MINT,
        expected_source_owner=SOURCE_OWNER,
        expected_destination_owner=DESTINATION_OWNER,
        expected_amount_atomic="100",
    )


def status_fixture() -> dict[str, JsonValue]:
    return {
        "value": [
            {
                "confirmationStatus": "confirmed",
                "err": None,
                "slot": 123,
            }
        ]
    }


def transaction_fixture() -> dict[str, JsonValue]:
    return {
        "slot": 123,
        "meta": {
            "err": None,
            "preTokenBalances": [
                token_balance(0, SOURCE_OWNER, "1000"),
                token_balance(1, DESTINATION_OWNER, "100"),
            ],
            "postTokenBalances": [
                token_balance(0, SOURCE_OWNER, "900"),
                token_balance(1, DESTINATION_OWNER, "200"),
            ],
        },
        "transaction": {
            "message": {
                "accountKeys": [
                    {"pubkey": SOURCE_ACCOUNT, "signer": False, "writable": True},
                    DESTINATION_ACCOUNT,
                ]
            }
        },
    }


def token_balance(index: int, owner: str, amount: str) -> dict[str, JsonValue]:
    return {
        "accountIndex": index,
        "mint": X402_SOLANA_DEVNET_USDC_MINT,
        "owner": owner,
        "uiTokenAmount": {"amount": amount, "decimals": 6},
    }


def meta(transaction: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], transaction["meta"])


def message(transaction: dict[str, JsonValue]) -> dict[str, JsonValue]:
    raw_transaction = cast(dict[str, JsonValue], transaction["transaction"])
    return cast(dict[str, JsonValue], raw_transaction["message"])
