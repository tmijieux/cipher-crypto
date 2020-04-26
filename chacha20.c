#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <bsd/stdlib.h>

#include "chacha20.h"
#include "util.h"

static inline void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

static inline void chacha20_column_round(uint32_t *t)
{
    quarter_round(t+0, t+4, t+8, t+12);
    quarter_round(t+1, t+5, t+9, t+13);
    quarter_round(t+2, t+6, t+10, t+14);
    quarter_round(t+3, t+5, t+11, t+15);
}

static inline void chacha20_diagonal_round(uint32_t *t)
{
    quarter_round(t+0, t+5, t+10, t+15);
    quarter_round(t+1, t+6, t+11, t+12);
    quarter_round(t+2, t+7, t+8, t+13);
    quarter_round(t+3, t+4, t+9, t+14);
}

void chacha20_print_state(chacha20_state_t *state)
{
    printf("\ncounter = %lu\n", state->counter);
    printf("state = ");

    for (unsigned i = 0; i < ARRAY_SIZE(state->state) ; ++i)
    {
        printf("%08x ", state->state[i]);
    }
    printf("\n");
}


void chacha20_cipher_encrypt(chacha20_state_t *state)
{
    uint32_t t[16];
    memcpy(t, state->state, sizeof state->state);

    for (unsigned i = 0; i < 10; ++i)
    {
        chacha20_column_round(t);
        chacha20_diagonal_round(t);
    }

    for (unsigned i = 0; i < ARRAY_SIZE(state->state); ++i)
    {
        state->state[i] += t[i];
    }
}


void chacha20_reset_state(chacha20_state_t *state)
{
   // 0 - 3 constant bytes
    memcpy(state->state, "expand 32-byte k", 4*4);

    // 4 - 11 key
    memcpy(state->state+4, state->key, CHACHA20_KEY_LEN);

    // 12 - 13 stream counter
    memcpy(state->state+12, &state->counter, sizeof state->counter);

    // 14-15 nonce
    memcpy(state->state+14, &state->nonce, sizeof state->nonce);
}


/* counter mode */
void chacha20_encrypt(chacha20_state_t *state,
                      uint8_t *in_data, uint8_t *out_data, size_t len)
{
    state->counter = 0;

    for (size_t i = 0; i < len; i += sizeof state->state)
    {
        chacha20_reset_state(state);
        chacha20_cipher_encrypt(state);

        // xor state with cleartext
        uint32_t buf[16] = {0};
        size_t siz = MIN(len - i, sizeof state->state);
        memcpy(buf, in_data+i, siz);
        for (unsigned i = 0; i < 16; ++i)
            buf[i] ^= state->state[i];
        memcpy(out_data+i, buf, siz);

        ++state->counter;
    }
}


void chacha20_decrypt(chacha20_state_t *state,
                      uint8_t *in_data, uint8_t *out_data, size_t len)
{
    chacha20_encrypt(state, in_data, out_data, len);
}

void chacha20_init(chacha20_state_t *state)
{
    memset(state, 0, sizeof *state);
    arc4random_buf(state->key, CHACHA20_KEY_LEN);
    arc4random_buf(&state->nonce, sizeof state->nonce);
}
