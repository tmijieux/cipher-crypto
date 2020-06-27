#include <bsd/stdlib.h>
#include <string.h>

#include "rc4.h"

// !!! RC4 is not considered safe anymore !!!


static void rc4_key_schedule(rc4_state_t *state)
{
    const uint8_t *const K = state->key;
    uint8_t *const S = state->state;

    for (unsigned i = 0; i < 256; ++i)
    {
        S[i] = (uint8_t) i;
    }

    uint8_t j = 0;

    for (unsigned i = 0; i < 256; ++i)
    {
        j = j + S[i] + K[i % RC4_KEY_LEN];
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
}

void rc4_reset_state(rc4_state_t *state)
{
    rc4_key_schedule(state);
}


void rc4_encrypt(rc4_state_t *state, uint8_t *in_data, uint8_t *out_data, size_t len)
{

    uint8_t *const S = state->state;
    uint8_t i = 0;
    uint8_t j = 0;
    for (size_t k = 0; k < len; k++)
    {
        ++i;
        j += S[i];
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;

        uint8_t c = S[S[i] + S[j]];
        out_data[k] = in_data[k] ^ c;
    }
}


void rc4_decrypt(rc4_state_t *state,
                 uint8_t *in_data, uint8_t *out_data, size_t len)
{
    rc4_encrypt(state, in_data, out_data, len);
}


void rc4_init(rc4_state_t *state)
{
    memset(state, 0, sizeof *state);
    arc4random_buf(state->key, sizeof state->key);
}
