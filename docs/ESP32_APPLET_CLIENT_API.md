# ESP32 Applet Client API

This document defines the `ESP32S3`-side client layer used to talk to `SatochipApplet`.

The client layer is the boundary between:

- the closed-wallet device state machine on `ESP32S3`
- the secure signing core inside `SatochipApplet`

It is not a generic smartcard SDK. It is a product-specific wallet client for the phase-1 closed-wallet architecture.

## Goals

- hide raw APDU framing behind a narrow wallet-oriented API
- keep card-session handling explicit and deterministic
- map applet status words into stable device-side error categories
- support both applet stacks:
  - legacy `BIP32 + secp256k1`
  - `Ed25519 + SLIP-0010`
- fit the device state machine defined in [DEVICE_STATE_MACHINE.md](./DEVICE_STATE_MACHINE.md)

## Non-goals

- direct desktop use of the applet client
- exposing arbitrary raw APDU passthrough to companion software
- treating the applet as a generic multi-tenant card service

## Layering

The `ESP32S3` firmware should split card access into four layers.

```text
wallet flows
  bitcoin_flow / solana_flow / provisioning_flow
        |
        v
applet client facade
  wallet_client
        |
        v
session layer
  card_session / secure_channel / pin_state
        |
        v
transport layer
  iso7816 transport / reader bridge / slot control
```

## Module layout

Suggested firmware-side layout:

```text
firmware/
  card/
    transport/
      card_transport.h
      card_transport.c
    protocol/
      apdu.h
      apdu.c
      sw_map.h
      sw_map.c
    session/
      card_session.h
      card_session.c
      secure_channel_client.h
      secure_channel_client.c
    applet/
      satochip_client.h
      satochip_client.c
      satochip_types.h
      satochip_types.c
```

## Primary responsibilities

### Transport layer

Owns:

- physical card presence detection
- APDU send and receive
- reset or reconnect behavior

Does not own:

- applet semantics
- secure-channel logic
- wallet-policy decisions

### Session layer

Owns:

- applet selection
- secure-channel establishment
- PIN verification state
- session invalidation on card removal, timeout, or applet failure

Does not own:

- chain-specific derivation or signing policy

### Applet client facade

Owns:

- typed wrappers around applet instructions
- response parsing
- status-word mapping
- wallet-facing data structures

Does not own:

- transaction parsing
- user-confirmation screens
- blockchain-specific host logic

## API design principles

- all functions return explicit status codes
- raw status words are preserved for logging and diagnostics
- no hidden global session state outside a context object
- functions requiring an unlocked session must fail fast if PIN state is invalid
- public APIs should be typed around wallet operations, not APDU bytes

## Core data types

Suggested C-style structures:

```c
typedef enum {
    SATO_OK = 0,
    SATO_ERR_NO_CARD,
    SATO_ERR_TRANSPORT,
    SATO_ERR_APPLET_NOT_FOUND,
    SATO_ERR_SECURE_CHANNEL,
    SATO_ERR_PIN_REQUIRED,
    SATO_ERR_PIN_FAILED,
    SATO_ERR_CARD_LOCKED,
    SATO_ERR_UNPROVISIONED,
    SATO_ERR_PARTIAL_PROVISIONING,
    SATO_ERR_INVALID_PATH,
    SATO_ERR_INVALID_ARGUMENT,
    SATO_ERR_UNSUPPORTED,
    SATO_ERR_BUSY,
    SATO_ERR_INTERNAL,
    SATO_ERR_APPLET_SW
} sato_result_t;

typedef struct {
    uint8_t sw1;
    uint8_t sw2;
    uint16_t sw;
} sato_status_word_t;

typedef struct {
    bool card_present;
    bool applet_selected;
    bool secure_channel_open;
    bool pin_verified;
    bool setup_done;
    bool bip32_seeded;
    bool ed25519_seeded;
    uint8_t pin0_tries_remaining;
    uint8_t protocol_major;
    uint8_t protocol_minor;
    uint8_t applet_major;
    uint8_t applet_minor;
} sato_device_status_t;

typedef struct {
    bool initialized;
    bool card_present;
    bool applet_selected;
    bool secure_channel_open;
    bool pin_verified;
    sato_device_status_t last_status;
    sato_status_word_t last_sw;
} sato_session_t;
```

## Path types

The client layer should avoid raw string parsing at runtime. Paths should be normalized into fixed-width structures before card use.

```c
#define SATO_MAX_BIP32_DEPTH 10
#define SATO_MAX_ED25519_DEPTH 10

typedef struct {
    uint8_t depth;
    uint32_t components[SATO_MAX_BIP32_DEPTH];
} sato_bip32_path_t;

typedef struct {
    uint8_t depth;
    uint32_t components[SATO_MAX_ED25519_DEPTH];
} sato_ed25519_path_t;
```

Policy enforcement:

- Bitcoin phase 1 must accept only `m/84'/0'/0'/change/index`
- Solana phase 1 must accept only `m/44'/501'/0'/0'`

This policy check should happen before any APDU is sent.

## Public API

### Session and status

```c
sato_result_t sato_init_session(sato_session_t *session);
sato_result_t sato_card_detect(sato_session_t *session);
sato_result_t sato_select_applet(sato_session_t *session);
sato_result_t sato_get_status(sato_session_t *session, sato_device_status_t *out_status);
sato_result_t sato_open_secure_channel(sato_session_t *session);
sato_result_t sato_verify_pin(sato_session_t *session, const uint8_t *pin, size_t pin_len);
sato_result_t sato_logout(sato_session_t *session);
sato_result_t sato_invalidate_session(sato_session_t *session);
```

### Provisioning

```c
sato_result_t sato_setup_card(sato_session_t *session, const uint8_t *pin, size_t pin_len);
sato_result_t sato_import_bip32_seed(sato_session_t *session, const uint8_t *seed, size_t seed_len);
sato_result_t sato_reset_bip32_seed(sato_session_t *session, const uint8_t *pin, size_t pin_len);
sato_result_t sato_import_ed25519_seed(sato_session_t *session, const uint8_t *seed, size_t seed_len);
sato_result_t sato_reset_ed25519_seed(sato_session_t *session, const uint8_t *pin, size_t pin_len);
```

### Bitcoin / BIP32

```c
sato_result_t sato_get_bip32_authentikey(
    sato_session_t *session,
    uint8_t *out_pub65,
    size_t *out_len);

sato_result_t sato_get_bip32_extended_key(
    sato_session_t *session,
    const sato_bip32_path_t *path,
    uint8_t *out_chaincode32,
    uint8_t *out_pub65,
    size_t *out_pub_len);

sato_result_t sato_sign_bip32_tx_hash(
    sato_session_t *session,
    const uint8_t tx_hash[32],
    uint8_t *out_der_sig,
    size_t *out_sig_len);
```

Phase-1 note:

- the applet client should only expose the subset required by the Bitcoin product flow
- advanced message-signing or non-standard derivation helpers should stay internal or be omitted

### Ed25519 / Solana

```c
sato_result_t sato_get_ed25519_public_key(
    sato_session_t *session,
    const sato_ed25519_path_t *path,
    uint8_t out_pub32[32]);

sato_result_t sato_sign_ed25519(
    sato_session_t *session,
    const sato_ed25519_path_t *path,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_sig64[64]);
```

## Internal command mapping

The applet client should centralize instruction mapping in one place.

Suggested command table:

```text
INS_SETUP                    0x2A
INS_GET_STATUS               0x3C
INS_VERIFY_PIN               0x42
INS_LOGOUT_ALL               0x60
INS_BIP32_IMPORT_SEED        0x6C
INS_BIP32_GET_EXTENDED_KEY   0x6D
INS_BIP32_GET_AUTHENTIKEY    0x73
INS_BIP32_RESET_SEED         0x77
INS_SIGN_TRANSACTION_HASH    0x7A
INS_ED25519_IMPORT_SEED      0x7B
INS_ED25519_RESET_SEED       0x7C
INS_ED25519_GET_PUBLIC_KEY   0x7D
INS_ED25519_SIGN             0x7E
INS_INIT_SECURE_CHANNEL      0x81
INS_PROCESS_SECURE_CHANNEL   0x82
```

## Required call patterns

### Boot and status discovery

```text
sato_card_detect
  -> sato_select_applet
  -> sato_get_status
  -> state-machine classification
```

### Unlock flow

```text
sato_select_applet
  -> sato_open_secure_channel
  -> sato_verify_pin
  -> sato_get_status
```

### New-wallet provisioning flow

```text
device creates or restores mnemonic
  -> derive BIP39 seed on ESP32S3
  -> sato_select_applet
  -> sato_open_secure_channel
  -> if setup not done: sato_setup_card
  -> sato_verify_pin
  -> sato_import_bip32_seed
  -> sato_import_ed25519_seed
  -> sato_get_status
  -> validate both domains provisioned
  -> wipe mnemonic and seed buffers
```

### Partial-provision repair flow

```text
sato_get_status
  -> if only one domain provisioned:
       attempt missing import
       or reset both domains and restart provisioning
```

### Bitcoin signing flow

```text
proposal accepted from companion
  -> wallet layer validates BIP84 policy
  -> wallet layer reconstructs review model
  -> user approves on-device
  -> sato_sign_bip32_tx_hash
  -> signature returned to wallet layer
  -> signed result exported to companion
```

### Solana signing flow

```text
proposal accepted from companion
  -> wallet layer validates canonical Solana path
  -> wallet layer parses supported SOL transfer
  -> user approves on-device
  -> sato_sign_ed25519
  -> signature returned to wallet layer
  -> signed result exported to companion
```

## Response parsing rules

The applet client should parse all length-prefixed outputs inside one protocol module.

Important conventions already used by the applet:

- many outputs are returned as `[size(2 bytes) | payload]`
- `GET_STATUS` contains fixed-position fields and debug bytes
- Ed25519 public key is 32 bytes
- Ed25519 signature is 64 bytes

The wallet layer should never parse APDU payloads directly.

## Status-word mapping

The applet client must preserve raw SW values but normalize them into device-side categories.

Suggested mapping examples:

- `0x9000` -> `SATO_OK`
- `0x9C06` and unauthorized cases -> `SATO_ERR_PIN_REQUIRED`
- PIN retry failure range -> `SATO_ERR_PIN_FAILED`
- `0x9C0C` or blocked identity cases -> `SATO_ERR_CARD_LOCKED`
- `0x9C14` -> `SATO_ERR_UNPROVISIONED`
- `0x9C50` -> `SATO_ERR_UNPROVISIONED`
- `0x9C52` -> `SATO_ERR_INVALID_PATH`
- `0x9C53` -> `SATO_ERR_UNSUPPORTED`
- `0xE3xx`, `0xE4xx`, `0xE5xx`, `0xECxx`, `0xEDxx`, `0xEExx` -> `SATO_ERR_INTERNAL`

All unmapped values should return:

- `SATO_ERR_APPLET_SW`

with the original `sw1`, `sw2`, and `sw`.

## Session invalidation rules

The applet client must invalidate the current unlocked session when:

- card is removed
- secure-channel sequence is lost
- PIN verification fails in a terminal way
- a transport reset occurs
- the state machine transitions to `ERROR_RECOVERY`

When invalidated:

- `secure_channel_open = false`
- `pin_verified = false`
- all in-flight signing or provisioning buffers must be cleared

## Memory rules on ESP32S3

The client layer must not hold secret material longer than required.

Rules:

- PIN buffers are zeroized after verification attempts
- BIP39 seed buffer is zeroized after dual import completes or fails
- transaction proposal buffers are cleared after approval or rejection
- received signatures are copied out only to caller-owned buffers

The client layer should avoid heap allocation for small fixed-size command buffers.

## Logging rules

Allowed logs:

- high-level operation names
- device state transitions
- raw status words
- non-secret public metadata

Forbidden logs:

- PIN bytes
- mnemonic words
- BIP39 seed
- private key material
- decrypted sensitive transaction blobs not needed for diagnostics

## Concurrency rules

Phase 1 should assume a single active card session and a single foreground wallet flow.

Do not support:

- parallel APDU commands
- concurrent provisioning and signing
- companion-driven background signing jobs

## Recommended next implementation steps

1. define the concrete `card_transport` API for your ESP32S3 hardware design
2. implement `GET_STATUS`, applet select, and secure-channel bootstrap
3. implement PIN verification and session invalidation
4. implement dual-seed provisioning helpers
5. implement Bitcoin and Solana typed signing wrappers
6. wire the client into the device state machine
