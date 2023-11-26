#ifndef _PARAMETERS_CPP
#define _PARAMETERS_CPP

#include "parameters.h"

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
// #include "../ciphers/rsa/rsa_interface.h"

using namespace std;

#define SIZE_OF_AES128_KEY 16

SymmCipher CIPHER;
bit128_t SECRET_KEY;  
EVP_PKEY* RSA_KEY;

//Forward declaration of INTERFACE functions
void aes128_set_key(bit128_t key); 
void initialize_rng(int seed); 
void initialize_mersenne_rng(int seed);
void save_public_key(EVP_PKEY *pkey, const char *filename);
void rsa_set_key(EVP_PKEY *pkey);
EVP_PKEY *generate_rsa_key();


void setParameters(){
    CIPHER = XOR; 
    SECRET_KEY.init(0, 5);
    initialize_mersenne_rng(1);
}

void setParameters(SymmCipher cipher){
    CIPHER = cipher; 
    initialize_mersenne_rng(1);

    unsigned char raw_key[SIZE_OF_AES128_KEY];
    if (RAND_bytes(raw_key, SIZE_OF_AES128_KEY) != 1)
        throw std::runtime_error("Error generating random bytes for AES key");
    
    uint64_t upper = 0, lower = 0;
    for (int i = 0; i < 8; ++i) {
        upper = (upper << 8) | raw_key[i];
        lower = (lower << 8) | raw_key[i + 8];
    }
    SECRET_KEY.init(upper, lower);

    switch(CIPHER){
        case AES128:    aes128_set_key(SECRET_KEY); break;
        default:    break;
    }
}

void setParameters(SymmCipher cipher, uint64_t key_upper, uint64_t key_lower, int seed){
    CIPHER = cipher; 
    SECRET_KEY.init(key_upper, key_lower);      
    initialize_mersenne_rng(seed);

    switch(CIPHER){
        case AES128:    aes128_set_key(SECRET_KEY); break;
        default:    break;
    }
}

void setParameters_XOR(uint64_t key_upper, uint64_t key_lower, int seed){
    CIPHER = SymmCipher::XOR; 
    SECRET_KEY.init(key_upper, key_lower);      
    initialize_mersenne_rng(seed);
}

void setRSAParameters() { 
    RSA_KEY = generate_rsa_key();
    // save_private_key(RSA_KEY, "private_key.pem");
    // save_public_key(RSA_KEY, "public_key.pem");
    rsa_set_key(RSA_KEY);
}

#endif
