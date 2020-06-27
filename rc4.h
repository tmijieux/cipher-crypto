#ifndef RC4_H
#define RC4_H

#include <stdint.h>
#include <stdlib.h>

#define RC4_STATE_LEN         256   // 16 * 4
#define RC4_KEY_LEN           256   // 16 * 4

struct rc4_state {
    uint8_t state[RC4_STATE_LEN];
    uint8_t key[RC4_KEY_LEN];
};
typedef struct rc4_state rc4_state_t;


void rc4_init(rc4_state_t *state);
void rc4_encrypt(rc4_state_t *state,
                 uint8_t *in_data, uint8_t *out_data, size_t len);
void rc4_decrypt(rc4_state_t *state,
                 uint8_t *in_data, uint8_t *out_data, size_t len);
void rc4_reset_state(rc4_state_t *state);


#endif // RC4_H
