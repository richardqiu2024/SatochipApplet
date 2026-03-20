# Platform TODO

This file is the execution checklist for the `ESP32 + SatochipApplet` hardware-wallet platform.

Scope:

- `SatochipApplet` remains the main JavaCard applet
- `ESP32S3` is the primary wallet host
- `BIP39` is handled on `ESP32S3`
- `secp256k1/BIP32` and `Ed25519/SLIP-0010` both remain first-class
- first release target is `Bitcoin + Solana`
- desktop or mobile software is companion-only

Reference architecture:

- [docs/ESP32_WALLET_PLATFORM_PLAN.md](docs/ESP32_WALLET_PLATFORM_PLAN.md)
- [docs/ED25519_INTEGRATION.md](docs/ED25519_INTEGRATION.md)

## 0. Baseline control

- [x] Integrate `Ed25519 + SLIP-0010` into `SatochipApplet`
- [x] Preserve existing Satochip `BIP32` flows after Ed25519 integration
- [x] Add real-card smoke test for Ed25519
- [x] Add real-card regression test covering legacy Satochip flow plus Ed25519
- [x] Record build, install, and debug notes in repository docs
- [x] Freeze a known-good CAP build and record the applet baseline for platform work

## 1. Applet hardening

- [ ] Review all Ed25519 APDUs for length checks, state checks, and failure-path cleanup
- [ ] Audit transient and persistent memory use around `recvBuffer` reuse
- [ ] Add explicit status bytes or debug flags only where they are safe for production
- [ ] Define final status-word map for Ed25519 and platform-specific failures
- [ ] Add negative tests for malformed hardened paths
- [ ] Add negative tests for unauthorized Ed25519 access before PIN validation
- [ ] Add tests for repeated seed import and reset edge cases
- [ ] Add tests for large-message Ed25519 signing boundaries
- [ ] Decide whether Ed25519 and BIP32 seeds must be linked or remain independent
- [ ] Document the production APDU contract for the dual-stack applet

## 2. Applet feature gaps

- [x] Decide the exact seed model for the platform:
  `Phase 1`: one `BIP39`-derived 64-byte seed is derived on `ESP32S3` and imported into both `BIP32` and `Ed25519`
- [x] Define deterministic path policy for Bitcoin and Solana accounts
- [ ] Decide whether the applet needs a generic "get public key by chain profile" APDU wrapper
- [ ] Decide whether transaction review hashes should be prepared on `ESP32S3` or partially canonicalized in applet helpers
- [ ] Keep `BIP39` off-card unless a strict product requirement proves otherwise

## 3. ESP32 platform foundation

- [ ] Create the `ESP32` firmware repository layout
- [x] Define the closed-wallet device state machine
- [ ] Implement the applet client layer on `ESP32S3`
- [ ] Decide the companion link types for phase 1:
  USB only, or USB plus BLE
- [ ] Implement APDU framing and card-session management on `ESP32`
- [ ] Implement applet selection, secure channel setup, PIN verification, and status polling
- [ ] Add a hardware-abstraction layer for screen, buttons, and storage
- [ ] Add a secure memory-wipe utility for sensitive temporary buffers
- [ ] Define what account and transaction state is cached locally on the device

## 4. BIP39 on ESP32

- [ ] Add mnemonic generation
- [ ] Add mnemonic checksum validation
- [ ] Add optional passphrase support
- [ ] Add `PBKDF2-HMAC-SHA512` seed derivation
- [ ] Add import flow from derived seed into `BIP32`
- [ ] Add import flow from derived seed into `Ed25519`
- [ ] Define whether both imports happen automatically from one mnemonic or are profile-driven
- [ ] Add screen flow for mnemonic display and confirmation
- [ ] Add screen flow for mnemonic restore
- [ ] Define secure wipe policy for mnemonic and derived seed buffers

## 5. Bitcoin path

- [x] Define supported account types for phase 1:
  native SegWit single-sig `BIP84` only
- [x] Choose the exact derivation paths to support first:
  `m/84'/0'/0'/change/index`
- [ ] Implement public-key export and address display flow through `ESP32`
- [ ] Implement companion-to-device Bitcoin proposal intake format
- [ ] Implement on-device Bitcoin transaction reconstruction and review model
- [x] Decide whether phase 1 uses raw legacy tx flow, SegWit only, or PSBT:
  `PSBT v0` host exchange, SegWit-only wallet policy
- [ ] Implement signing request flow from companion to `ESP32S3` to card
- [ ] Display amount, destination, and fee on screen before approval
- [ ] Validate signatures against a host-side reference
- [ ] Test repeated sign operations on real cards

## 6. Solana path

- [x] Lock the supported derivation path policy for phase 1:
  `m/44'/501'/0'/0'`
- [ ] Implement Ed25519 public-key export flow through `ESP32`
- [ ] Implement Solana address encoding and display
- [x] Define the transaction or message types supported in phase 1:
  standard SOL transfer flow only
- [ ] Implement companion-to-device Solana proposal intake format
- [ ] Implement Solana message parsing on `ESP32`
- [ ] Display signer, destination, amount, and fee-relevant data before approval
- [ ] Implement signing request flow from companion to `ESP32S3` to card
- [ ] Validate Ed25519 signatures against a host-side reference
- [ ] Test repeated derive-sign cycles on real cards

## 7. Companion integration

- [ ] Define the companion-to-`ESP32S3` transport protocol
- [ ] Build a minimal desktop companion app for firmware integration
- [ ] Build a minimal mobile companion app if phase 1 requires it
- [ ] Add a Bitcoin companion harness
- [ ] Add a Solana companion harness
- [ ] Define version negotiation between companion, `ESP32S3`, and applet
- [ ] Define error propagation so applet status words are preserved in companion logs

## 8. UI and safety

- [ ] Define a consistent approval UX for all signing actions
- [ ] Define a cancellation UX for partial operations
- [ ] Add PIN entry UX on `ESP32S3`
- [ ] Add lockout and retry UX for bad PIN cases
- [ ] Add recovery UX for card missing, wrong applet, and secure-channel failures
- [ ] Define how much raw transaction data is ever shown to the user

## 9. Validation and release

- [ ] Keep the existing real-card regression suite passing on every applet change
- [ ] Add a firmware-side automated integration test runner
- [ ] Add performance measurements for derive and sign on real cards
- [ ] Record tested reader models and tested card models
- [ ] Add a release checklist covering CAP build, install, regression, and firmware compatibility
- [ ] Produce a versioned compatibility matrix for applet, firmware, and host tool versions

## 10. Stretch goals after Bitcoin + Solana

- [ ] Ethereum / EVM support on the existing `secp256k1` stack
- [ ] Aptos support on the current Ed25519 stack
- [ ] Sui support on the current Ed25519 stack
- [ ] Stellar support on the current Ed25519 stack
- [ ] Tezos support on the current Ed25519 stack
- [ ] NEAR support on the current Ed25519 stack

## 11. Voice interaction

- [x] Define the voice UX boundary:
  phase 1 is query and navigation only, no voice signing
- [ ] Decide the on-device speech frontend architecture
- [ ] Define wake-word and explicit listening modes
- [x] Define safe voice commands for phase 1 voice support
- [x] Require physical confirmation for every value-moving action
- [x] Define how voice failure and ambiguity are surfaced to the user

## 12. AI assistance

- [x] Define the AI trust boundary:
  advisory only in phase 1, not signing authority
- [ ] Define the market and chain data sources
- [x] Define the structured proposal format returned by AI services
- [ ] Define the on-device rule engine that validates AI proposals
- [ ] Define user risk controls:
  whitelist, max size, slippage, venue, daily limit
- [x] Define whether AI support is cloud, local-server, or companion-assisted in each product mode
- [x] Define how AI rationale and confidence are displayed on-device

## Immediate next actions

- [x] Freeze the current `SatochipApplet` baseline and CAP hash
- [x] Define the phase-1 seed model
- [x] Define phase-1 Bitcoin scope
- [x] Define phase-1 Solana scope
- [x] Define the closed-wallet device state machine
- [x] Scaffold the `ESP32S3` applet client layer
