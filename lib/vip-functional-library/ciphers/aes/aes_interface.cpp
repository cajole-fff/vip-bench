#ifndef _AES_INTERFACE_CPP
#define _AES_INTERFACE_CPP

#include "aes_interface.h"
#include <iostream>


struct aes128 ctx_encrypt[1];
struct aes128 ctx_decrypt[1];

bool ctx_encrypt_initialized = false;
bool ctx_decrypt_initialized = false;

void aes128_set_encrypt_key(bit128_t key_pass) {
    fprintf(stderr, "aes128_set_encrypt_key\n");
    aes128_init(ctx_encrypt, key_pass.value);
    ctx_encrypt_initialized = true;
}

void aes128_set_decrypt_key(bit128_t key_pass) {
    fprintf(stderr, "aes128_set_decrypt_key\n");
    aes128_init(ctx_decrypt, key_pass.value);
    ctx_decrypt_initialized = true;
}


bool encrypt_used = false;

bit128_t aes128_encrypt_128(bit128_t plaintext) {
    // if (!ctx_encrypt_initialized) {
    //     throw std::runtime_error("Error: aes128_encrypt_128 called before aes128_set_encrypt_key");
    // }
    
    if (!encrypt_used) {
        fprintf(stderr, "aes128_encrypt_128\n");
    }
    // Use gdb to find out where this is called from
    
    encrypt_used = true;
    unsigned char ct[AES128_BLOCKLEN] = {0};
    aes128_encrypt(ctx_encrypt, ct, plaintext.value);

    return bit128_t(ct);
}


bit128_t aes128_decrypt_128(bit128_t ciphertext){
    if (!ctx_decrypt_initialized) {
        throw std::runtime_error("Error: aes128_decrypt_128 called before aes128_set_decrypt_key");
    }
    unsigned char pt[AES128_BLOCKLEN] = {0};
    aes128_decrypt(ctx_decrypt, pt, ciphertext.value);

    return bit128_t(pt);
}


#endif
