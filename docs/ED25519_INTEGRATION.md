# Ed25519 Integration Notes

This document records the current Ed25519 and SLIP-0010 integration work for `SatochipApplet`, including build settings, CAP install commands, real-card test commands, and the status words used during debugging.

## Current branch state

- Build file: [build.xml](../build.xml)
- JavaCard SDK configured in `build.xml`: `sdks/jc305u4_kit`
- Output CAP: `SatoChip-3.0.4.cap`
- Applet AID: `5361746F4368697000`
- Package AID: `5361746F43686970`
- Current protocol version: `0.12`
- Current applet version from `GET_STATUS`: `0.10`
  Source: [CardEdge.java](../src/org/satochip/applet/CardEdge.java)

The Ed25519 service is lazily initialized and now reuses the applet `recvBuffer` as its work buffer instead of allocating extra byte arrays at startup.

Relevant sources:

- [CardEdge.java](../src/org/satochip/applet/CardEdge.java)
- [Ed25519Service.java](../src/org/satochip/applet/Ed25519Service.java)
- [Slip10Ed25519.java](../src/org/satochip/applet/Slip10Ed25519.java)
- [test_ed25519.py](../scripts/test_ed25519.py)
- [test_satochip_regression.py](../scripts/test_satochip_regression.py)
- [test_sensitive_failure_paths.py](../scripts/test_sensitive_failure_paths.py)
- [run_realcard_pipeline.py](../scripts/run_realcard_pipeline.py)
- [WSL_DOCKER_JAVACARD_WORKFLOW.md](./WSL_DOCKER_JAVACARD_WORKFLOW.md)

## Frozen baseline

The current platform baseline for follow-on `ESP32 + SatochipApplet` work is:

- Git commit: `02ed3d5356fd94f3c76810682a66054e19b3fb3b`
- CAP file: `SatoChip-3.0.4.cap`
- CAP SHA-256: `22E4A2E4AF9A14BF46C4AE19AA1FCAC15B7C48CDE474A22AC2ECFEE61BBE6A9C`

This baseline is the known-good applet state to use before starting `ESP32`-side transport, `BIP39`, Bitcoin, and Solana integration work.

Validation status recorded for this baseline:

- CAP install succeeded on the target card
- Ed25519 smoke test passed on a real card
- Combined legacy Satochip plus Ed25519 regression passed on a real card

If a future applet change breaks platform work, compare against this baseline first.

## Build

Default build command:

```bash
ant
```

This uses the `javacard` Ant task declared in [build.xml](../build.xml) and generates:

```text
SatoChip-3.0.4.cap
```

The build was verified with JDK 11 and `jc305u4_kit`.

## Install on card

List content on the card:

```bash
gp -r "ACS ACR1281 1S Dual Reader 00 01" \
  --key 404142434445464748494A4B4C4D4E4F \
  -l
```

Delete the installed Satochip package and its dependencies:

```bash
gp -r "ACS ACR1281 1S Dual Reader 00 01" \
  --key 404142434445464748494A4B4C4D4E4F \
  --delete 5361746F43686970 \
  --deletedeps
```

Install the CAP:

```bash
gp -r "ACS ACR1281 1S Dual Reader 00 01" \
  --key 404142434445464748494A4B4C4D4E4F \
  --install SatoChip-3.0.4.cap
```

On this branch, `CAP loaded` followed by a transport failure during `installAndMakeSelectable` was fixed by making Ed25519 initialization lazy. A successful install now completes without touching Ed25519 allocation paths.

## Test scripts

### Ed25519-only smoke test

This checks the custom Ed25519 APDUs on a real card:

```bash
python3 scripts/test_ed25519.py \
  --reader "ACS ACR1281 1S Dual Reader 00 01" \
  --pin 123456 \
  --setup \
  --reset-before \
  --debug
```

If the host environment is missing `cryptography` or `PyNaCl`, use:

```bash
python3 scripts/test_ed25519.py \
  --reader "ACS ACR1281 1S Dual Reader 00 01" \
  --pin 123456 \
  --setup \
  --reset-before \
  --debug \
  --no-reference
```

### Full Satochip + Ed25519 regression

This is the more important test for integration. It proves that legacy Satochip flows still work after Ed25519 import and signing.

```bash
python3 scripts/test_satochip_regression.py \
  --reader "ACS ACR1281 1S Dual Reader 00 01" \
  --pin 123456 \
  --setup \
  --reset-before \
  --debug
```

What it covers:

- secure channel setup
- card setup and PIN verification
- `INS_EXPORT_AUTHENTIKEY`
- `INS_BIP32_IMPORT_SEED`
- `INS_BIP32_GET_AUTHENTIKEY`
- `INS_BIP32_GET_EXTENDED_KEY`
- `INS_SIGN_MESSAGE`
- `INS_SIGN_TRANSACTION_HASH`
- `INS_ED25519_IMPORT_SEED`
- `INS_ED25519_GET_PUBLIC_KEY`
- `INS_ED25519_SIGN`
- BIP32 post-check after the Ed25519 flow

Observed passing summary:

```text
Summary:
  PASS secure_channel/setup/pin
  PASS reset_before_bip32
  PASS reset_before_ed25519
  PASS bip32_smoke
  PASS ed25519_smoke
  PASS bip32_postcheck_after_ed25519
Result: PASS
```

Interpretation:

- `PASS bip32_smoke` means legacy Satochip derivation and signing still work.
- `PASS ed25519_smoke` means the integrated Ed25519 flow works.
- `PASS bip32_postcheck_after_ed25519` means the Ed25519 service did not corrupt BIP32 state.

### Failure-path security regression

This branch also includes a dedicated regression for the sensitive-buffer cleanup and stale-key invalidation changes:

```bash
python3 scripts/test_sensitive_failure_paths.py \
  --reader "ACS ACR1281 1S Dual Reader 00 01" \
  --pin 123456 \
  --setup \
  --reset-before \
  --debug
```

Or run it as part of the full real-card pipeline:

```bash
python3 scripts/run_realcard_pipeline.py \
  --reader "ACS ACR1281 1S Dual Reader 00 01" \
  --pin 123456 \
  --setup \
  --reset-before \
  --debug \
  --no-reference
```

What it covers:

- protected commands sent outside the secure channel are rejected with `0x9C20`
- `INS_PROCESS_SECURE_CHANNEL` rejects use before initialization with `0x9C21`
- truncated secure-channel envelopes are rejected with `0x6700`
- tampered secure-channel MAC is rejected with `0x9C23`
- even or replayed secure-channel IV values are rejected with `0x9C22`
- the secure channel remains usable after those failures
- reselecting the applet invalidates the previous secure-channel session until a fresh handshake is performed
- invalid-length `INS_BIP32_IMPORT_SEED` is rejected
- signing with `key_nb = 0xFF` before `INS_BIP32_GET_EXTENDED_KEY` is rejected with `0x9C13`
- `INS_SIGN_TRANSACTION` also rejects a missing temporary BIP32 extended key
- `INS_SIGN_TRANSACTION_HASH` also rejects a missing temporary BIP32 extended key
- a valid BIP32 derive still allows successful signing afterward
- after a valid derive, `INS_SIGN_TRANSACTION` advances to the expected transaction-hash check
- resetting and re-importing BIP32 seed does not preserve a stale cached temporary key
- invalid-length `INS_ED25519_IMPORT_SEED` is rejected
- malformed `INS_ED25519_SIGN` payload is rejected
- Ed25519 public-key export and signing still work after the failed Ed25519 request

Observed passing summary:

```text
Summary:
  PASS secure_channel_rejects_raw_protected_command
  PASS secure_channel_rejects_uninitialized_process
  PASS secure_channel/setup/pin
  PASS reset_before
  PASS secure_channel_rejects_truncated_envelope
  PASS secure_channel_rejects_wrong_mac
  PASS secure_channel_rejects_even_iv
  PASS secure_channel_recovers_after_tamper
  PASS secure_channel_rejects_stale_session_after_reselect
  PASS secure_channel_recovers_after_reselect
  PASS bip32_import_rejects_bad_length
  PASS bip32_sign_rejects_missing_extended_key
  PASS bip32_tx_sign_rejects_missing_extended_key
  PASS bip32_hash_sign_rejects_missing_extended_key
  PASS bip32_sign_succeeds_after_derivation
  PASS bip32_tx_sign_reaches_txhash_check_after_derivation
  PASS bip32_reset_clears_cached_extended_key
  PASS bip32_reset_clears_cached_extended_key_for_tx_sign
  PASS ed25519_import_rejects_bad_length
  PASS ed25519_sign_rejects_bad_length
  PASS ed25519_recovers_after_failed_sign
Result: PASS
```

This script does not directly read card RAM or EEPROM. Instead, it checks the externally visible invariants that matter for this hardening work:

- no stale temporary BIP32 extended key can be reused after invalid or incomplete setup
- Ed25519 failure paths do not poison the next valid request
- secure-channel integrity and session-boundary failures do not leave the applet stuck in a bad state

For the exact container command sequence used during validation, see [WSL_DOCKER_JAVACARD_WORKFLOW.md](./WSL_DOCKER_JAVACARD_WORKFLOW.md).

## Sensitive buffer hardening

The current branch hardens exception paths that use the shared `recvBuffer` work area.

Files changed:

- [CardEdge.java](../src/org/satochip/applet/CardEdge.java)

Main changes:

- `try/finally` cleanup was added to:
  - `importBIP32Seed()`
  - `getBIP32ExtendedKey()`
  - `importEd25519Seed()`
  - `getEd25519PublicKey()`
  - `signEd25519()`
- `bip32_extendedkey` is now explicitly invalidated on:
  - `resetSeed()`
  - failed `getBIP32ExtendedKey()`
- BIP32 temporary-key validity is tracked explicitly instead of relying only on `ECPrivateKey.clearKey()`
- signing with `key_nb = 0xFF` now requires a valid temporary derived key in:
  - `signMessage()`
  - `SignTransaction()`
  - `SignTransactionHash()`

Security intent:

- sensitive BIP32 and Ed25519 scratch state is wiped even when the APDU exits via `ISOException`
- stale cached temporary BIP32 private keys are not silently reused after failure or reset

Important implementation note:

- clearing `bip32_extendedkey` with `clearKey()` alone caused subsequent `INS_BIP32_GET_EXTENDED_KEY` operations to fail with `0x6F00` on the target card
- the fix was to keep an explicit `bip32_extendedkey_valid` state bit and re-apply secp256k1 domain parameters when invalidating the key object

## Extended status bytes

`INS_GET_STATUS` now includes Ed25519 debug bytes at the end of the response.

Fields added by this branch:

- `ed25519_service_ready`
- `ed25519_seeded`
- `ed25519_last_init_sw`
- `ed25519_init_attempts`
- `ed25519_allocator_strategy`
- `ed25519_buffer_strategy`

Source:

- [CardEdge.java](../src/org/satochip/applet/CardEdge.java)

Typical successful values after Ed25519 import:

```text
ed25519_ready         : True
ed25519_seeded        : True
ed25519_last_init_sw  : 0x9000
ed25519_init_attempts : 1
ed25519_allocator     : 1
ed25519_buf_strategy  : 3
```

Buffer strategy `3` means the Ed25519 service is using the shared `recvBuffer` work area.

## Status words

Ed25519-specific status words from [CardEdge.java](../src/org/satochip/applet/CardEdge.java):

- `0x9C50`: Ed25519 seed is not initialized
- `0x9C51`: Ed25519 seed is already initialized
- `0x9C52`: Ed25519 path is invalid, non-hardened, or malformed
- `0x9C53`: Ed25519 service is unavailable

Ed25519 service staged initialization status words from [Ed25519Service.java](../src/org/satochip/applet/Ed25519Service.java):

- `0xE3xx`: `CryptoException` during `Ed25519Service` initialization
- `0xE4xx`: `SystemException` during `Ed25519Service` initialization
- `0xE5xx`: `CardRuntimeException` during `Ed25519Service` initialization

The low byte is the initialization stage.

JCMathLib resource manager staged status words from [jcmathlib.java](../src/org/satochip/applet/jcmathlib.java):

- `0xECxx`: `CryptoException` during `ResourceManager` setup
- `0xEDxx`: `SystemException` during `ResourceManager` setup
- `0xEExx`: `CardRuntimeException` during `ResourceManager` setup

## Important debug result from this branch

The original integration failure on the real card was:

```text
INS_ED25519_IMPORT_SEED failed with SW=0xE408
```

Meaning:

- `0xE4xx`: `SystemException`
- low byte `0x08`: `Ed25519Service` stage 8

At that point, the code was still trying to allocate extra work arrays. The standalone `JCEd25519` applet could afford this, but the integrated `SatochipApplet` already had much higher RAM pressure.

The fix was:

- lazy Ed25519 service initialization
- shared `recvBuffer` work area
- explicit debug bytes in `INS_GET_STATUS`

The work-buffer requirement is currently:

- `Ed25519Service.REQUIRED_WORK_BUFFER_SIZE = 225`
  Source: [Ed25519Service.java](../src/org/satochip/applet/Ed25519Service.java)

## Recommended release check

Before committing or tagging this branch, run:

1. `python3 scripts/run_realcard_pipeline.py --reader "ACS ACR1281 1S Dual Reader 00 01" --pin 123456 --setup --reset-before --debug --no-reference`
2. If you need a focused Ed25519-only sanity check, run `python3 scripts/test_ed25519.py ...`

Do not treat `Ed25519` as validated unless the serial real-card pipeline passes on the target card.
