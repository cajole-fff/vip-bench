#ifndef _AES_INTERFACE_CPP
#define _AES_INTERFACE_CPP

#include "aes_interface.h"
#include <iostream>


struct aes128 ctx_encrypt[1];
struct aes128 ctx_decrypt[1];

// void aes128_set_key(bit128_t key_pass){
//     aes128_init(ctx_encrypt, key_pass.value);
// }

void aes128_set_encrypt_key(bit128_t key_pass){
    aes128_init(ctx_encrypt, key_pass.value);
}

void aes128_set_decrypt_key(bit128_t key_pass){
    aes128_init(ctx_decrypt, key_pass.value);
}


bit128_t aes128_encrypt_128(bit128_t plaintext){
    unsigned char ct[AES128_BLOCKLEN] = {0};
    aes128_encrypt(ctx_encrypt, ct, plaintext.value);

    return bit128_t(ct);
}


bit128_t aes128_decrypt_128(bit128_t ciphertext){
    unsigned char pt[AES128_BLOCKLEN] = {0};
    aes128_decrypt(ctx_encrypt, pt, ciphertext.value);

    return bit128_t(pt);
}


#endif
