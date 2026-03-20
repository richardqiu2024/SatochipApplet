# Device State Machine

This document defines the phase-1 closed-wallet state machine for the `ESP32S3 + SatochipApplet` hardware wallet.

The goal is to make `ESP32S3` the effective wallet host while keeping `SatochipApplet` as the secure signing core.

## Design goals

- all sensitive signing decisions are made on-device
- companion software is never trusted as signing authority
- partial provisioning states are detected and repaired or rejected
- the UI always reflects the real security state of the device

## State overview

The device should expose these top-level states:

1. `BOOT`
2. `NO_CARD`
3. `CARD_DETECTED`
4. `APPLET_MISMATCH`
5. `UNPROVISIONED`
6. `PARTIALLY_PROVISIONED`
7. `LOCKED`
8. `UNLOCKED`
9. `SIGNING_REVIEW`
10. `BUSY_OPERATION`
11. `ERROR_RECOVERY`

## State definitions

### `BOOT`

Entry:

- device powers on
- firmware resets

Actions:

- initialize screen, buttons, storage, and secure memory utilities
- detect card presence
- attempt applet selection

Exit:

- to `NO_CARD`
- to `CARD_DETECTED`
- to `APPLET_MISMATCH`

### `NO_CARD`

Meaning:

- no usable JavaCard is present

Actions:

- show insert-card prompt
- allow passive companion connection for diagnostics only

Exit:

- to `CARD_DETECTED` when a card is inserted and applet select succeeds
- to `APPLET_MISMATCH` when a card is present but the required applet is missing

### `CARD_DETECTED`

Meaning:

- card transport is live
- applet can be selected
- device must query applet status before deciding operational mode

Actions:

- issue `GET_STATUS`
- inspect setup state, secure-channel requirement, and seed-domain state

Exit:

- to `UNPROVISIONED`
- to `PARTIALLY_PROVISIONED`
- to `LOCKED`
- to `ERROR_RECOVERY`

### `APPLET_MISMATCH`

Meaning:

- card is present, but the expected Satochip applet is not installed or not selectable

Actions:

- show mismatch warning
- expose read-only diagnostics to companion software

Exit:

- to `NO_CARD`
- to `CARD_DETECTED` after correct card or applet is present

### `UNPROVISIONED`

Meaning:

- wallet setup is incomplete, or neither `BIP32` nor `Ed25519` wallet domain is provisioned

Actions:

- allow setup flow
- allow mnemonic restore or new-wallet creation on-device
- allow secure provisioning into both applet seed domains

Exit:

- to `LOCKED` after successful setup and dual import
- to `PARTIALLY_PROVISIONED` if only one domain is imported
- to `ERROR_RECOVERY` if setup fails mid-flight

### `PARTIALLY_PROVISIONED`

Meaning:

- exactly one of the wallet seed domains is provisioned
- this is an abnormal state for the closed-wallet product

Actions:

- block normal wallet use
- offer repair flow:
  - complete the missing import
  - or reset both domains and reprovision cleanly

Exit:

- to `LOCKED` after successful repair
- to `UNPROVISIONED` after full reset
- to `ERROR_RECOVERY` on repeated failure

### `LOCKED`

Meaning:

- wallet is provisioned
- card is present
- signing is not allowed until PIN validation succeeds

Actions:

- allow watch-only account display
- allow public-key and address queries if product policy permits
- allow PIN entry

Exit:

- to `UNLOCKED` after successful PIN verification and secure-channel setup
- to `ERROR_RECOVERY` after transport or applet failure
- remain `LOCKED` after bad PIN attempts until tries are exhausted

### `UNLOCKED`

Meaning:

- secure channel is active if required
- PIN has been verified
- signing-capable commands are allowed

Actions:

- allow address export
- allow transaction proposal intake
- allow on-device review preparation

Exit:

- to `SIGNING_REVIEW`
- to `LOCKED` on timeout, logout, or card reinsertion
- to `ERROR_RECOVERY` on transport or applet failure

### `SIGNING_REVIEW`

Meaning:

- device has parsed a concrete transaction proposal
- the user must approve or reject it locally

Actions:

- show chain-specific review screens
- require physical confirmation on-device
- only after approval, request signature from applet

Exit:

- to `BUSY_OPERATION` after approval
- to `UNLOCKED` after rejection or cancellation
- to `ERROR_RECOVERY` on parse or sign failure

### `BUSY_OPERATION`

Meaning:

- device is actively running a non-interruptible security-sensitive operation

Examples:

- secure provisioning
- seed import rollback
- signature request in flight
- reset flow

Actions:

- block conflicting commands
- show progress or wait state

Exit:

- to `LOCKED`
- to `UNLOCKED`
- to `ERROR_RECOVERY`

### `ERROR_RECOVERY`

Meaning:

- the device detected an abnormal condition that must be resolved before normal operation continues

Examples:

- card removed during operation
- secure channel failure
- applet status inconsistency
- partial provisioning after rollback failure

Actions:

- surface a specific error code and recovery option
- clear transient buffers
- if needed, force logout and rebuild card session

Exit:

- to `NO_CARD`
- to `CARD_DETECTED`
- to `LOCKED`
- to `UNPROVISIONED`

## Provisioning policy

Provisioning is complete only when all of the following are true:

- card setup is complete
- secure-channel prerequisites are satisfied
- `BIP32` seed domain is provisioned
- `Ed25519` seed domain is provisioned

If only one seed domain is present, the device must enter `PARTIALLY_PROVISIONED`.

## Session policy

The device should define a session as:

- one unlocked period after PIN verification
- bound to current card presence
- invalidated by timeout, reset, card removal, or explicit logout

When a session ends:

- clear all transient proposal buffers
- clear mnemonic or derived-seed buffers if any still exist
- force state back to `LOCKED` or `NO_CARD`

## Companion policy

The companion app is not allowed to move the device directly into a signing state.

The companion may:

- request account data
- submit unsigned transaction proposals
- request broadcast of already signed payloads
- display state mirrored from the device

The companion may not:

- override path policy
- approve signing
- bypass device review screens
- treat the applet as a direct peripheral

## Phase-1 chain-specific entry rules

### Bitcoin

A Bitcoin signing proposal may only enter `SIGNING_REVIEW` if:

- the device is in `UNLOCKED`
- the path family matches `m/84'/0'/0'/change/index`
- the transaction proposal can be reconstructed into a supported SegWit single-sig flow

### Solana

A Solana signing proposal may only enter `SIGNING_REVIEW` if:

- the device is in `UNLOCKED`
- the path matches `m/44'/501'/0'/0'`
- the transaction is a supported standard SOL transfer

## Recommended implementation order

1. implement state detection from applet `GET_STATUS`
2. implement provisioning transitions
3. implement lock and unlock transitions
4. implement chain-specific proposal intake
5. implement review and sign transitions
6. implement error recovery and rollback handling
