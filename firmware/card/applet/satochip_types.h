#ifndef SATOCHIP_TYPES_H
#define SATOCHIP_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SATO_PIN_MIN_LEN 4u
#define SATO_PIN_MAX_LEN 16u
#define SATO_BIP39_SEED_LEN 64u
#define SATO_BIP32_CHAINCODE_LEN 32u
#define SATO_ED25519_PUBKEY_LEN 32u
#define SATO_ED25519_SIG_LEN 64u

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
    bool needs_secure_channel;
    bool needs_2fa;
    bool bip32_seeded;
    bool ed25519_ready;
    bool ed25519_seeded;
    uint8_t pin0_tries_remaining;
    uint8_t protocol_major;
    uint8_t protocol_minor;
    uint8_t applet_major;
    uint8_t applet_minor;
    uint16_t ed25519_last_init_sw;
    uint8_t ed25519_init_attempts;
    uint8_t ed25519_allocator_strategy;
    uint8_t ed25519_work_buffer_strategy;
} sato_device_status_t;

#ifdef __cplusplus
}
#endif

#endif
