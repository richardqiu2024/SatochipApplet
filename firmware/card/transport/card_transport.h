#ifndef CARD_TRANSPORT_H
#define CARD_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../applet/satochip_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CARD_APDU_MAX_DATA_LEN 268u

typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    const uint8_t *data;
    size_t data_len;
    bool has_le;
    uint16_t le;
} card_apdu_command_t;

typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t len;
    uint8_t sw1;
    uint8_t sw2;
    uint16_t sw;
} card_apdu_response_t;

struct card_transport;
typedef struct card_transport card_transport_t;

typedef sato_result_t (*card_transport_connect_fn)(card_transport_t *transport);
typedef sato_result_t (*card_transport_disconnect_fn)(card_transport_t *transport);
typedef sato_result_t (*card_transport_card_present_fn)(card_transport_t *transport, bool *out_present);
typedef sato_result_t (*card_transport_transceive_fn)(
    card_transport_t *transport,
    const card_apdu_command_t *command,
    card_apdu_response_t *response);
typedef sato_result_t (*card_transport_reset_fn)(card_transport_t *transport);

struct card_transport {
    void *impl;
    card_transport_connect_fn connect;
    card_transport_disconnect_fn disconnect;
    card_transport_card_present_fn is_card_present;
    card_transport_transceive_fn transceive;
    card_transport_reset_fn reset;
};

sato_result_t card_transport_command_validate(const card_apdu_command_t *command);
sato_result_t card_transport_response_reset(card_apdu_response_t *response);

#ifdef __cplusplus
}
#endif

#endif
