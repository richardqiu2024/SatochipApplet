#ifndef CARD_SESSION_H
#define CARD_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../transport/card_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool initialized;
    bool card_present;
    bool applet_selected;
    bool secure_channel_open;
    bool pin_verified;
    card_transport_t *transport;
    sato_device_status_t last_status;
    sato_status_word_t last_sw;
} sato_session_t;

void sato_session_reset(sato_session_t *session);
sato_result_t sato_session_attach_transport(sato_session_t *session, card_transport_t *transport);
sato_result_t sato_session_refresh_presence(sato_session_t *session, bool *out_present);
void sato_session_set_last_sw(sato_session_t *session, uint8_t sw1, uint8_t sw2);
void sato_session_invalidate(sato_session_t *session);
bool sato_session_is_ready(const sato_session_t *session);
bool sato_session_is_unlocked(const sato_session_t *session);
bool sato_session_has_card(const sato_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
