#ifndef SATOCHIP_CLIENT_H
#define SATOCHIP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "../session/card_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SATO_MAX_BIP32_DEPTH 10u
#define SATO_MAX_ED25519_DEPTH 10u
#define SATO_AUTHENTIKEY_MAX_LEN 65u
#define SATO_EXTENDED_PUBKEY_MAX_LEN 65u
#define SATO_DER_SIGNATURE_MAX_LEN 80u

typedef struct {
    uint8_t depth;
    uint32_t components[SATO_MAX_BIP32_DEPTH];
} sato_bip32_path_t;

typedef struct {
    uint8_t depth;
    uint32_t components[SATO_MAX_ED25519_DEPTH];
} sato_ed25519_path_t;

typedef struct {
    uint8_t chain_code[SATO_BIP32_CHAINCODE_LEN];
    uint8_t public_key[SATO_EXTENDED_PUBKEY_MAX_LEN];
    size_t public_key_len;
} sato_bip32_extended_key_t;

sato_result_t sato_init_session(sato_session_t *session);
sato_result_t sato_card_detect(sato_session_t *session);
sato_result_t sato_select_applet(sato_session_t *session);
sato_result_t sato_get_status(sato_session_t *session, sato_device_status_t *out_status);
sato_result_t sato_open_secure_channel(sato_session_t *session);
sato_result_t sato_verify_pin(sato_session_t *session, const uint8_t *pin, size_t pin_len);
sato_result_t sato_logout(sato_session_t *session);
sato_result_t sato_invalidate_session(sato_session_t *session);

sato_result_t sato_setup_card(sato_session_t *session, const uint8_t *pin, size_t pin_len);
sato_result_t sato_import_bip32_seed(sato_session_t *session, const uint8_t *seed, size_t seed_len);
sato_result_t sato_reset_bip32_seed(sato_session_t *session, const uint8_t *pin, size_t pin_len);
sato_result_t sato_import_ed25519_seed(sato_session_t *session, const uint8_t *seed, size_t seed_len);
sato_result_t sato_reset_ed25519_seed(sato_session_t *session, const uint8_t *pin, size_t pin_len);

sato_result_t sato_get_bip32_authentikey(
    sato_session_t *session,
    uint8_t *out_pubkey,
    size_t out_capacity,
    size_t *out_len);

sato_result_t sato_get_bip32_extended_key(
    sato_session_t *session,
    const sato_bip32_path_t *path,
    sato_bip32_extended_key_t *out_key);

sato_result_t sato_sign_bip32_tx_hash(
    sato_session_t *session,
    const uint8_t tx_hash[32],
    uint8_t *out_der_sig,
    size_t out_capacity,
    size_t *out_sig_len);

sato_result_t sato_get_ed25519_public_key(
    sato_session_t *session,
    const sato_ed25519_path_t *path,
    uint8_t out_pubkey[SATO_ED25519_PUBKEY_LEN]);

sato_result_t sato_sign_ed25519(
    sato_session_t *session,
    const sato_ed25519_path_t *path,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_sig[SATO_ED25519_SIG_LEN]);

bool sato_policy_is_phase1_bitcoin_path(const sato_bip32_path_t *path);
bool sato_policy_is_phase1_solana_path(const sato_ed25519_path_t *path);

#ifdef __cplusplus
}
#endif

#endif
