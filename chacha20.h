#ifndef CHACHA20_H
#define CHACHA20_H


#define CHACHA20_KEY_LEN       32
#define CHACHA20_KEY_LEN_WORD  8

#define CHACHA20_BLOCK_LEN         64   // 16 * 4
#define CHACHA20_BLOCK_LEN_WORD    16

struct chacha20_state {
    uint32_t state[CHACHA20_BLOCK_LEN_WORD];
    uint8_t key[CHACHA20_KEY_LEN];
    uint64_t nonce;
    uint64_t counter;
};
typedef struct chacha20_state chacha20_state_t;


void chacha20_init(chacha20_state_t *state);
void chacha20_encrypt(chacha20_state_t *state,
                      uint8_t *in_data, uint8_t *out_data, size_t len);
void chacha20_decrypt(chacha20_state_t *state,
                      uint8_t *in_data, uint8_t *out_data, size_t len);


#endif // CHACHA20_H
