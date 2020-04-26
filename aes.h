#ifndef AES_H
#define AES_H

#define KLEN 256

#if KLEN == 128

#define AES_KEY_BIT_COUNT 128
#define AES_ROUND_COUNT   10
#define AES_KEY_LEN       16
#define AES_KEY_LEN_WORD  4

#elif KLEN == 192

#define AES_KEY_BIT_COUNT 192
#define AES_ROUND_COUNT   12
#define AES_KEY_LEN       24
#define AES_KEY_LEN_WORD  6

#elif KLEN == 256

#define AES_KEY_BIT_COUNT 256
#define AES_ROUND_COUNT   14
#define AES_KEY_LEN       32
#define AES_KEY_LEN_WORD  8

#endif

#define AES_BLOCK_BIT_COUNT 128
#define AES_BLOCK_LEN       16  // number of bytes
#define AES_BLOCK_LEN_WORD   4 // number of 4 bytes words


struct aes_state {
    uint8_t subst_box[256]; // rijndael S-box
    uint8_t inv_subst_box[256];  // inverse rijndael S-box

    uint8_t key[AES_KEY_LEN];
    uint8_t iv[AES_KEY_LEN];
    uint8_t round_keys[(AES_ROUND_COUNT+1)*AES_BLOCK_LEN];

    uint8_t state[AES_BLOCK_LEN];
};
typedef struct aes_state aes_state_t;

void aes_init(aes_state_t *state);

void aes_cbc_iv_encrypt(aes_state_t *state,
                        uint8_t *in_data, uint8_t *out_data, size_t len);
void aes_cbc_iv_decrypt(aes_state_t *state,
                        uint8_t *in_data, uint8_t *out_data, size_t len);

void aes_ecb_encrypt(aes_state_t *state,
                     uint8_t *in_data, uint8_t *out_data, size_t len);
void aes_ecb_decrypt(aes_state_t *state,
                     uint8_t *in_data, uint8_t *out_data, size_t len);


#endif // AES_H
