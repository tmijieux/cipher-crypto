#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <bsd/stdlib.h>

#include "aes.h"
#include "util.h"

const uint32_t round_constants[10] = {
    0x00000001,
    0x00000002,
    0x00000004,
    0x00000008,
    0x00000010,
    0x00000020,
    0x00000040,
    0x00000080,
    0x0000001B,
    0x00000036,
};

static inline uint32_t substword(aes_state_t *state, uint32_t word)
{
    uint8_t *buf = (uint8_t*)&word;
    for (unsigned i = 0; i < sizeof word; ++i)
    {
        buf[i] = state->subst_box[buf[i]];
    }
    return word;
}

static inline uint32_t rotword(uint32_t word)
{
    uint8_t *buf = (uint8_t*)&word;
    uint8_t tmp = buf[0];
    buf[0] = buf[1];
    buf[1] = buf[2];
    buf[2] = buf[3];
    buf[3] = tmp;

    return word;
}

void aes_key_schedule(aes_state_t *state)
{
    const int N = AES_KEY_LEN_WORD;
    uint32_t K[AES_KEY_LEN_WORD];
    memcpy(K, state->key, sizeof K);

    const int R = AES_ROUND_COUNT + 1;
    uint32_t W[(AES_ROUND_COUNT+1)*AES_BLOCK_LEN_WORD];

    for (unsigned i = 0; i < AES_BLOCK_LEN_WORD * R; ++i)
    {
        if (i < N)
        {
            W[i] = K[i];
        }
        else if (i >= N && (i % N) == 0)
        {
            W[i] = W[i-N] ^ (substword(state, rotword(W[i-1]))) ^ round_constants[i/N];
        }
        else if (i >= N && N > 6 && (i % N) == 4)
        {
            W[i] = W[i-N] ^ substword(state, W[i-1]);
        }
        else
        {
            W[i] = W[i-N] ^ W[i-1];
        }
    }

    memcpy(state->round_keys, W, sizeof W);
}

void aes_print_key(aes_state_t *state)
{
    printf("key = \t\t\t");
    for (unsigned i = 0; i < AES_KEY_LEN; ++i) {
        printf("%02x", state->key[i]);
    }
    printf("\n");
}

void aes_print_round_keys(aes_state_t *state)
{
    for (unsigned i = 0; i < (AES_ROUND_COUNT+1); ++i)
    {
        printf("round key [%d] = \t", i);
        for (unsigned j = 0; j < AES_BLOCK_LEN; ++j)
        {
            printf("%02x", state->round_keys[i*AES_BLOCK_LEN + j]);
        }
        printf("\n");
    }
}

void initialize_aes_sbox(uint8_t sbox[256])
{
    uint8_t p = 1, q = 1;

    /* loop invariant: p * q == 1 in the Galois field */
    do {
        /* multiply p by 3 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        /* compute the affine transformation */
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

        sbox[p] = xformed ^ 0x63;
    } while (p != 1);

    /* 0 is a special case since it has no inverse */
    sbox[0] = 0x63;
}

void initialize_aes_inverse_sbox(const uint8_t sbox[256],
                                 uint8_t inv_sbox[256])
{

    for (unsigned i = 0; i < 256; ++i)
    {
        inv_sbox[sbox[i]] = (uint8_t)i;
    }
}

/*
  multiply two elements of Galois Field
  a and b are element of GF(2^8) (polynomials)
*/
static inline uint8_t gf_mult(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (unsigned counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
            p ^= a;
        }
        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

/* return a = a * b (mod x^4+1)
   a, b, and d are polynomials are four-term polynomials
   where coefficients are element of GF(2^8)
   (i.e polynomials whom coefficients themselves are polynomials)
*/
static inline void generic_mixcolumn_polynomial_mult(uint8_t a[4], uint8_t b[4])
{
    uint8_t t[4];
    memcpy(t, a, sizeof t);

    uint8_t c[7];
    c[0] = gf_mult(t[0], b[0]);
    c[1] = gf_mult(t[1], b[0]) ^ gf_mult(t[0], b[1]);
    c[2] = gf_mult(t[2], b[0]) ^ gf_mult(t[1], b[1]) ^ gf_mult(t[0], b[2]);
    c[3] = gf_mult(t[3], b[0]) ^ gf_mult(t[2], b[1]) ^ gf_mult(t[1], b[2]) ^ gf_mult(t[0], b[3]);
    c[4] = gf_mult(t[3], b[1]) ^ gf_mult(t[2], b[2]) ^ gf_mult(t[1], b[3]);
    c[5] = gf_mult(t[3], b[2]) ^ gf_mult(t[2], b[3]);
    c[6] = gf_mult(t[3], b[3]);

    a[0] = c[0] ^ c[4];
    a[1] = c[1] ^ c[5];
    a[2] = c[2] ^ c[6];
    a[3] = c[3];
}

static inline void aes_mixcolumn_forward(uint8_t *ptr)
{
    uint8_t pol[4] = { 2, 1, 1, 3 };
    for (unsigned i = 0; i < 4; ++i)
    {
        generic_mixcolumn_polynomial_mult(ptr+4*i, pol);
    }
}

static inline void aes_mixcolumn_inverse(uint8_t *ptr)
{
    uint8_t pol[4] = { 14, 9, 13, 11 };
    for (unsigned i = 0; i < 4; ++i)
    {
        generic_mixcolumn_polynomial_mult(ptr+4*i, pol);
    }
}

static inline void aes_shift_rows_forward(uint8_t *b)
{
    // 2nd row
    // b[1] b[5]  b[9]  b[13] <- 1 byte left shift
    uint8_t tmp = b[1];
    b[1] = b[5];
    b[5] = b[9];
    b[9] = b[13];
    b[13] = tmp;

    // 3rd row
    // b[2] b[6]  b[10] b[14]<- 2 bytes left shift
    tmp = b[2]; b[2] = b[10]; b[10] = tmp;
    tmp = b[6]; b[6] = b[14]; b[14] = tmp;

    // 4th row
    // b[3] b[7]  b[11] b[15] <- 3 bytes left shift
    tmp = b[3];
    b[3] = b[15];
    b[15] = b[11];
    b[11] = b[7];
    b[7] = tmp;
}

static inline void aes_shift_rows_inverse(uint8_t *b)
{
    // 2nd row
    // b[1] b[5]  b[9]  b[13] <- 1 byte right shift
    uint8_t tmp = b[13];
    b[13] = b[9];
    b[9] = b[5];
    b[5] = b[1];
    b[1] = tmp;

    // 3rd row
    // b[2] b[6]  b[10] b[14]<- 2 bytes right shift
    tmp = b[2]; b[2] = b[10]; b[10] = tmp;
    tmp = b[6]; b[6] = b[14]; b[14] = tmp;

    // 4th row
    // b[3] b[7]  b[11] b[15] <- 3 bytes right shift
    tmp = b[7];
    b[7] = b[11];
    b[11] = b[15];
    b[15] = b[3];
    b[3] = tmp;
}

void aes_cipher_encrypt(aes_state_t *state)
{
    uint64_t key[2];
    uint64_t buf[2];
    uint8_t *ptr = (uint8_t*)buf;

    // initial round AddRoundKey (XOR)
    _Static_assert(sizeof key == AES_BLOCK_LEN);
    _Static_assert(sizeof buf == AES_BLOCK_LEN);

    memcpy(buf, state->state, AES_BLOCK_LEN);
    memcpy(key, state->round_keys, AES_BLOCK_LEN);
    buf[0] ^= key[0];
    buf[1] ^= key[1];

    // intermediate rounds
    for (unsigned round = 1; round <= AES_ROUND_COUNT; ++round)
    {
        // SubBytes
        for (size_t i = 0; i < AES_BLOCK_LEN; ++i)
        {
            ptr[i] = state->subst_box[ptr[i]];
        }

        aes_shift_rows_forward(ptr);
        if (round < AES_ROUND_COUNT)
        {
            aes_mixcolumn_forward(ptr);
        }

        // AddRoundKey (XOR)
        // get round key :
        memcpy(key, state->round_keys+(round*AES_BLOCK_LEN), AES_BLOCK_LEN);
        // apply XOR
        buf[0] ^= key[0];
        buf[1] ^= key[1];
    }
    memcpy(state->state, buf, AES_BLOCK_LEN);
}

/*
  each block is XORed with previous ciphertext as iv
  first clear text use state->iv (random)

  (insecure)
*/
void aes_cbc_iv_encrypt(aes_state_t *state,
                        uint8_t *in_data, uint8_t *out_data, size_t len)
{
    // CBC initialize state to iv
    memcpy(state->state, state->iv, AES_BLOCK_LEN);

    for (size_t i = 0; i < len; i += AES_BLOCK_LEN)
    {
        // CBC (Cipher block chaining)

        size_t siz = MIN(len - i, AES_BLOCK_LEN);
        uint64_t buf[2] = {0,0};
        uint64_t iv[2];
        memcpy(iv, state->state, AES_BLOCK_LEN); // "load iv"
        memcpy(buf, in_data+i, siz);
        // CBC XOR cleartext with iv
        buf[0] ^= iv[0];
        buf[1] ^= iv[1];
        memcpy(state->state, buf, AES_BLOCK_LEN);

        aes_cipher_encrypt(state);
        memcpy(out_data+i, state->state, siz);
    }
}

/*
  each block is encrypted individually
  all block with same cleartext will have exactly same ciphertext
*/
void aes_ecb_encrypt(aes_state_t *state,
                     uint8_t *in_data, uint8_t *out_data, size_t len)
{
    for (size_t i = 0; i < len; i += AES_BLOCK_LEN)
    {
        // ECB ("Electronic codebook")
        size_t siz = MIN(len - i, AES_BLOCK_LEN);
        memset(state->state, 0, AES_BLOCK_LEN);
        memcpy(state->state, in_data, siz);
        aes_cipher_encrypt(state);
        memcpy(out_data+i, state->state, siz);
    }
}



/*  ------- decrypt --------- */


void aes_cipher_decrypt(aes_state_t *state)
{
    uint64_t key[2];
    uint64_t buf[2];
    uint8_t *ptr = (uint8_t*)buf;

    memcpy(buf, state->state, sizeof buf);

    // intermediate rounds
    for (unsigned round = AES_ROUND_COUNT; round >= 1; --round)
    {
        // AddRoundKey (XOR)
        // get round key :
        memcpy(key, state->round_keys+(round*AES_BLOCK_LEN), sizeof key);
        // apply XOR
        buf[0] ^= key[0];
        buf[1] ^= key[1];

        if (round < AES_ROUND_COUNT)
        {
            aes_mixcolumn_inverse(ptr);
        }

        aes_shift_rows_inverse(ptr);

        // inverse SubBytes
        for (size_t i = 0; i < AES_BLOCK_LEN; ++i)
        {
            ptr[i] = state->inv_subst_box[ptr[i]];
        }
    }

    memcpy(key, state->round_keys, sizeof buf);
    // inverse initial  AddRoundKey (XOR)
    buf[0] ^= key[0];
    buf[1] ^= key[1];
    memcpy(state->state, buf, sizeof buf);
}

/*
  each block is XORed with previous ciphertext as iv
  first clear text use state->iv (random)
*/
void aes_cbc_iv_decrypt(aes_state_t *state,
                        uint8_t *in_data, uint8_t *out_data, size_t len)
{
    uint64_t iv_next[2] = {0, 0};
    memcpy(iv_next, state->iv, AES_BLOCK_LEN);

    for (size_t i = 0; i < len; i += AES_BLOCK_LEN)
    {
        // CBC (Cipher block chaining)
        uint64_t iv[2] = {0, 0};
        /* 'load' iv for current block */
        memcpy(iv, iv_next, AES_BLOCK_LEN);

        /* save iv for next block */
        size_t siz = MIN(len - i, AES_BLOCK_LEN);
        memset(iv_next, 0, AES_BLOCK_LEN);
        memcpy(iv_next, in_data, siz);

        memset(state->state, 0, AES_BLOCK_LEN);
        memcpy(state->state, in_data, siz);
        aes_cipher_decrypt(state);

        uint64_t buf[2] = {0, 0};
        memcpy(buf, state->state, AES_BLOCK_LEN);
        buf[0] ^= iv[0];
        buf[1] ^= iv[1];

        memcpy(out_data+i, buf, siz);
    }
}


/*
  each block is encrypted individually
  all block with same cleartext will have exactly same ciphertext
*/
void aes_ecb_decrypt(aes_state_t *state,
                     uint8_t *in_data, uint8_t *out_data, size_t len)
{
    for (size_t i = 0; i < len; i += AES_BLOCK_LEN)
    {
        // ECB ("Electronic codebook")
        size_t siz = MIN(len - i, AES_BLOCK_LEN);
        memset(state->state, 0, AES_BLOCK_LEN);
        memcpy(state->state, in_data, siz);
        aes_cipher_decrypt(state);
        memcpy(out_data+i, state->state, siz);
    }
}

// TODO aes_gcm_encrypt
void aes_gcm_encrypt(aes_state_t *state,
                     uint8_t *in_data, uint8_t *out_data, size_t len)
{
    for (size_t i = 0; i < len; i += AES_BLOCK_LEN)
    {
        // ECB ("Electronic codebook")
        size_t siz = MIN(len - i, AES_BLOCK_LEN);
        memset(state->state, 0, AES_BLOCK_LEN);
        memcpy(state->state, in_data, siz);
        aes_cipher_decrypt(state);
        memcpy(out_data+i, state->state, siz);
    }
}


void aes_init(aes_state_t *state)
{
    memset(state, 0, sizeof *state);

    initialize_aes_sbox(state->subst_box);
    initialize_aes_inverse_sbox(state->subst_box, state->inv_subst_box);

    arc4random_buf(state->key, AES_KEY_LEN);
    arc4random_buf(state->iv, AES_BLOCK_LEN);

    aes_key_schedule(state);

    aes_print_key(state);
    aes_print_round_keys(state);
}

