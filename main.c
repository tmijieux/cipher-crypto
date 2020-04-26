#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <bsd/stdlib.h>

#include "chacha20.h"
#include "aes.h"


#define N 3000

void test_aes(void)
{
    uint8_t cleartext[N] = "Hello world!";
    uint8_t ciphertext[N]= "";
    uint8_t decryptedtext[N]= "";
    cleartext[N-1] = 0;
    ciphertext[N-1] = 0;
    decryptedtext[N-1] = 0;

    aes_state_t state;
    aes_init(&state);

    // encrypt
    aes_cbc_iv_encrypt(&state, cleartext, ciphertext, N-1);
    //aes_ecb_encrypt(&state, cleartext, ciphertext, N-1);

    // decrypt
    aes_cbc_iv_decrypt(&state, ciphertext, decryptedtext, N-1);
    //aes_ecb_decrypt(&state, ciphertext, decryptedtext, N-1);

    printf("\n");
    printf("cleartext = %s\n", cleartext);
    printf("ciphertext = %s\n", ciphertext);
    printf("decryptedtext = %s\n", decryptedtext);
}

void test_chacha20(void)
{
    uint8_t cleartext[N] = "Hello world!";
    uint8_t ciphertext[N]= "";
    uint8_t decryptedtext[N]= "";
    cleartext[N-1] = 0;
    ciphertext[N-1] = 0;
    decryptedtext[N-1] = 0;

    chacha20_state_t state;
    chacha20_init(&state);

    // encrypt
    chacha20_encrypt(&state, cleartext, ciphertext, N-1);

    // decrypt
    chacha20_decrypt(&state, ciphertext, decryptedtext, N-1);

    printf("\n");
    printf("cleartext = %s\n", cleartext);
    printf("ciphertext = %s\n", ciphertext);
    printf("decryptedtext = %s\n", decryptedtext);
}

int main(int argc, char *argv[])
{
    test_chacha20();
    return 0;
}
