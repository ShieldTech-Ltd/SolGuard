# Isolated Solana wallet signer

The protected wallet path in `solguard.wallet_signer` prevents an autonomous agent from directly
possessing or invoking the wallet key. It accepts only serialized transaction bytes plus a
SolGuard-signed authorization for the exact transaction.

## Two separate signatures

SolGuard authorization and a Solana wallet signature prove different facts:

1. The decision-side SolGuard issuer signs the authorized financial intent with an Ed25519 issuer
   key.
2. The isolated wallet verifies that authorization, reconstructs the transaction fields from the
   serialized bytes, atomically consumes the authorization, and only then asks its wallet backend
   to sign.

A Solana transaction is publicly inspectable and cryptographically signed; it is not encrypted.
SolGuard does not claim transaction confidentiality.

## Exact binding

The signed authorization binds all of these fields:

- agent identifier
- public wallet address
- recipient
- USDC token mint
- atomic amount
- Solana devnet network identifier
- canonical request digest
- request nonce
- request expiry
- authorization identifier and expiry

The wallet independently obtains the same fields through an injected serialized-transaction
inspector. Any difference is rejected before the private-key backend is called. Mainnet and any
token mint other than the configured Solana-devnet USDC mint are disabled.

## Single use and failures

Authorization identifiers are consumed through the existing atomic authorization-store protocol.
Only one concurrent or sequential caller can proceed. The authorization is deliberately consumed
before the backend call, so a signer failure cannot turn the same permission into a retryable
signing capability.

Missing, expired, replayed, malformed, incorrectly signed, or field-mismatched authorizations fail
closed. Inspector, store, clock, and signer failures also fail closed.

## Key isolation

The offline cryptographic backend loads a disposable 32-byte Ed25519 seed from
`SOLGUARD_DEVNET_WALLET_SEED` as standard Base64. The seed is never accepted from repository
configuration and is never included in receipts. A real devnet deployment can replace the injected
backend and transaction inspector without changing the authorization verifier.

The included `CanonicalTransactionCodec` is explicitly an offline deterministic fixture. It signs
real bytes with Ed25519 but does not claim to produce a Solana wire transaction or blockchain
settlement. Real transaction construction and RPC confirmation are separate integration evidence.

## Threat boundary

The model protects against a compromised agent, agent credential, tool, model, or manipulated
payment requirement while the wallet key remains isolated. Theft of an independently usable wallet
private key is outside this proof boundary; the architecture reduces that risk by never providing
the key or a raw signing method to the agent.
