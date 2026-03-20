# ESP32 Wallet Platform Plan

This document defines the target architecture for building a multi-chain hardware wallet platform around `SatochipApplet`, `ESP32S3`, and the current Ed25519 integration work.

## Goal

Use `SatochipApplet` as the single JavaCard applet for secure key custody and signing, then pair it with an `ESP32S3` controller that acts as the main wallet host, UI controller, and transaction engine.

This branch direction is:

- keep the existing Satochip `BIP32 + secp256k1` stack
- keep the integrated `Ed25519 + SLIP-0010` stack
- move `BIP39` mnemonic handling to the `ESP32S3` side
- support multiple chains by routing requests from `ESP32S3` to the correct applet flow
- keep desktop or mobile software as a companion surface only

## Why this split

`JavaCard` is the correct place for:

- secure seed storage
- path derivation
- signing
- PIN / secure channel / sensitive state transitions

`ESP32S3` is the correct place for:

- screen and buttons
- USB / BLE transport
- human-readable transaction review
- chain-specific transaction parsing
- `BIP39` mnemonic generation, validation, restore, and `PBKDF2-HMAC-SHA512`

Putting full `BIP39` inside the card is possible in theory but is a poor fit in practice because of EEPROM and RAM pressure, wordlist storage, and implementation complexity. The pragmatic target is to derive the wallet seed on `ESP32S3` and then import the resulting seed into the card.

## System architecture

```text
+-----------------------------------------------------------+
| ESP32S3 Wallet Controller                                  |
| - primary wallet host                                      |
| - UI, buttons, display                                     |
| - BIP39 mnemonic + PBKDF2                                  |
| - chain routing and policy                                 |
| - transaction parsing and confirmation                     |
| - APDU session manager                                     |
| - optional companion link                                  |
+---------------------------+-------------------------------+
                            |
                            v
+-----------------------------------------------------------+
| JavaCard: SatochipApplet                                   |
| - secure channel                                            |
| - PIN / setup / 2FA                                         |
| - BIP32 + secp256k1                                         |
| - Ed25519 + SLIP-0010                                       |
| - seed custody and on-card signing                          |
+-----------------------------------------------------------+
                            ^
                            |
+---------------------------+-------------------------------+
| Desktop / Mobile Companion App                             |
| - watch-only display                                        |
| - sync and relay helper                                     |
| - export/import helper                                      |
| - never trusted for signing decisions                       |
+-----------------------------------------------------------+
```

## Responsibility split

### JavaCard applet

- Own the root seed material after import
- Enforce authentication and policy checks
- Derive `secp256k1` keys for Bitcoin and EVM-style flows
- Derive `Ed25519` keys via hardened-only `SLIP-0010`
- Sign only after the device-facing controller has completed user confirmation

### ESP32S3 firmware

- Generate or restore mnemonic
- Derive wallet seed from mnemonic and passphrase
- Import the correct seed into the applet
- Act as the primary wallet state machine
- Parse chain-specific payloads into confirmation screens
- Route commands to the `BIP32` or `Ed25519` APDU set
- Maintain clean user interaction and transport state

### Companion software

- Display watch-only state and history
- Relay blockchain data or unsigned proposals if needed
- Broadcast signed transactions
- Never be trusted as the final authority for what is signed
- Never access or derive private key material

## Supported-curve strategy

The platform should be explicitly dual-stack.

### secp256k1 stack

Use the existing Satochip path for:

- Bitcoin
- Litecoin
- Bitcoin Cash / eCash
- Ethereum / EVM

### Ed25519 stack

Use the integrated Ed25519 path for:

- Solana
- Stellar
- Tezos
- Aptos
- Sui
- NEAR

## Coin support status

### Good fit for current Ed25519 implementation

- Solana
- Stellar
- Tezos
- Aptos
- Sui
- NEAR

These chains still need chain-level work on `ESP32S3` and companion side:

- derivation-path policy
- address formatting
- transaction message encoding
- review screen formatting

### Not covered by current Ed25519 implementation

- Cardano: needs `Ed25519-BIP32` / `CIP-1852`
- Polkadot: needs `sr25519`
- Monero: needs a dedicated protocol-specific design

## Minimum viable product

The first end-to-end platform milestone should be:

- Bitcoin on `BIP32 + secp256k1`
- Solana on `Ed25519 + SLIP-0010`

This gives one strong chain on each signing stack and proves the platform architecture without overextending the first release.

## Closed-wallet operating model

The intended product is a closed hardware wallet.

That means:

- `ESP32S3` is the effective wallet host
- `SatochipApplet` is the secure signing core
- desktop and mobile software are companion displays only

Operational rules:

- the final signing decision must be made entirely on the device
- the device must parse and validate the transaction request before sending a signing APDU
- the device must show enough transaction detail locally for safe approval
- companion software may relay data, but it is not the source of truth

## Phase-1 seed model

Phase 1 should use a single mnemonic root with dual on-card imports.

Definition:

- `ESP32S3` owns the mnemonic UX
- `ESP32S3` derives the standard `BIP39` seed from `mnemonic + optional passphrase`
- the derived `BIP39` seed is the canonical wallet root for the platform
- the same derived seed bytes are then imported into both applet stacks:
  - `INS_BIP32_IMPORT_SEED`
  - `INS_ED25519_IMPORT_SEED`

This is the recommended phase-1 model because it is:

- standard
- easy to reason about
- compatible with one-wallet UX
- sufficient for both Bitcoin and Solana

### Exact rule

The canonical root secret for a wallet profile is:

- `seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64)`

The `ESP32S3` must derive this 64-byte seed and then:

1. import it into the legacy Satochip `BIP32` flow
2. import the same 64-byte seed into the Ed25519 `SLIP-0010` flow

The applet already accepts this model:

- `BIP32` import accepts up to 64 bytes
- `Ed25519` import accepts 16 to 64 bytes

### Platform policy

For production wallet flows in phase 1:

- both seed domains should be treated as one logical wallet profile
- a wallet is considered fully provisioned only if both imports succeed
- if one import succeeds and the other fails, `ESP32S3` should attempt rollback of the successful import so the card does not remain half-configured

This keeps the UX simple and avoids split-brain wallet state.

### Why not separate seeds

Phase 1 should not use separate user-visible seed domains for `BIP32` and `Ed25519`.

That would create:

- confusing recovery UX
- more backup material
- ambiguous account identity across chains
- extra provisioning and reset logic

Separate seed domains may still exist as a developer or advanced profile later, but they should not be the default platform model.

### Important implementation note

The card does not need to store the raw `BIP39` seed permanently.

The practical phase-1 flow is:

- `ESP32S3` derives the 64-byte `BIP39` seed
- applet derives and stores its domain-specific master material
- `ESP32S3` wipes the mnemonic and seed buffers after import

This preserves the intended boundary:

- `ESP32S3` handles mnemonic UX and temporary seed derivation
- `JavaCard` handles long-term custody and signing

### Allowed low-level state

For debugging and migration, the applet may still expose independent `BIP32` and `Ed25519` seeded states.

However, the production `ESP32S3` UI should treat these mixed states as abnormal and should:

- either repair them by completing the missing import
- or reset and reprovision the wallet cleanly

## Phase-1 derivation-path policy

Phase 1 should use fixed, deterministic derivation families per chain and should reject out-of-scope paths in the production `ESP32S3` UI.

### Bitcoin

Use native SegWit `BIP84` only.

Path family:

- `m/84'/0'/account'/change/index`

Phase-1 policy:

- mainnet wallet profile only
- `account' = 0'` only
- `change` must be `0` or `1`
- `index` is a normal unhardened address index
- external receive addresses use `change = 0`
- internal change addresses use `change = 1`

Examples:

- first receive address: `m/84'/0'/0'/0/0`
- first change address: `m/84'/0'/0'/1/0`

Out of scope for phase 1:

- `BIP44`
- `BIP49`
- Taproot
- multisig
- non-standard path entry in the end-user UI

### Solana

Use hardened-only `SLIP-0010` Ed25519 derivation with a single canonical wallet family.

Path family:

- `m/44'/501'/account'/0'`

Phase-1 policy:

- `account' = 0'` only
- final component is fixed to `0'`
- all path components are hardened
- no user-selectable alternative Solana path families in the end-user UI

Example:

- default Solana account: `m/44'/501'/0'/0'`

Out of scope for phase 1:

- multiple competing Solana derivation families
- arbitrary hardened-depth paths from the end-user UI
- account discovery across incompatible wallet conventions

## Phase-1 Bitcoin scope

Bitcoin phase 1 should be intentionally narrow.

Supported:

- single-signature wallet
- native SegWit receive addresses
- address export for account `0'`
- transaction review on `ESP32`
- signing for standard spend flows from the supported `BIP84` account

Signing policy:

- `SIGHASH_ALL` only
- single key origin family only: `m/84'/0'/0'/change/index`
- no blind signing in the normal user flow

Recommended host/firmware transaction container:

- `PSBT v0` as the phase-1 host-side exchange format

This keeps the companion interface standard while still allowing `ESP32S3` to do proper review before sending the final digest to the applet.

Phase-1 review requirements on `ESP32S3`:

- source account
- destination address
- spend amount
- fee
- change output summary

Not in phase 1:

- Taproot
- multisig
- coin control UX
- arbitrary script support
- message signing UX
- advanced sighash modes
- direct support for legacy `P2PKH` and wrapped SegWit receive flows

## Phase-1 Solana scope

Solana phase 1 should also be intentionally narrow.

Supported:

- single-signer account on the canonical path
- address export for `m/44'/501'/0'/0'`
- public-key display on `ESP32`
- signing of standard SOL transfer transactions after on-device review

Phase-1 review requirements on `ESP32S3`:

- signer account
- recipient address
- lamport amount in human-readable SOL form
- fee-payer context
- recent blockhash presence

Recommended transaction policy:

- no blind signing in the normal user flow
- support one canonical account family only
- require structured Solana transaction parsing on `ESP32` before signing

Not in phase 1:

- SPL token transfers
- stake and vote program support
- arbitrary program invocation
- generic message signing exposed to end users
- versioned transaction expansion beyond the first supported implementation choice
- alternative Solana derivation-path families

## Current applet baseline

Already integrated in this repository:

- legacy Satochip `BIP32 + secp256k1`
- Ed25519 seed import
- `SLIP-0010` hardened path derivation
- Ed25519 public-key export
- Ed25519 signing
- real-card regression showing that Ed25519 did not break the existing Satochip flows

See also:

- [PRODUCT_ARCHITECTURE_AND_ROADMAP.md](./PRODUCT_ARCHITECTURE_AND_ROADMAP.md)
- [ED25519_INTEGRATION.md](./ED25519_INTEGRATION.md)
- [DEVICE_STATE_MACHINE.md](./DEVICE_STATE_MACHINE.md)
- [ESP32_APPLET_CLIENT_API.md](./ESP32_APPLET_CLIENT_API.md)
- [TODO.md](../TODO.md)

## Target firmware layout

```text
firmware/
  wallet_core/
  bip39/
  card/
  chains/
    bitcoin/
    solana/
  companion/
  ui/
```

Suggested ownership:

- `wallet_core`: chain registry, policy, account metadata
- `bip39`: mnemonic, checksum, passphrase, seed derivation
- `card`: APDU framing, secure channel helpers, high-level applet client
- `chains/bitcoin`: address encoding, PSBT intake, tx reconstruction, review model
- `chains/solana`: derivation path policy, message parsing, review model
- `companion`: watch-only sync, relay, export/import, and external display protocol
- `ui`: screens, input flow, approval steps, error handling

## Security assumptions

- The companion app is not trusted with private key material
- `ESP32S3` is the user-confirmation boundary
- `JavaCard` is the key-protection boundary
- Sensitive seed material on `ESP32S3` must be short-lived and actively wiped after import whenever possible
- Signing must always be preceded by a display-confirmed review step on `ESP32S3`

## Development order

1. Stabilize and document the current `SatochipApplet` dual-stack applet
2. Build the `ESP32S3` applet client layer
3. Add `BIP39` and seed-import flow on `ESP32S3`
4. Ship Bitcoin end-to-end
5. Ship Solana end-to-end
6. Add companion-only sync and relay support
7. Expand to more Ed25519 chains

## Non-goals for the first phase

- Cardano support
- Polkadot support
- Monero support
- on-card `BIP39` wordlist processing
- full multi-chain coverage in a single milestone
