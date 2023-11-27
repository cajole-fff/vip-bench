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

std::vector<unsigned char> ENCRYPTED_SECRET_KEY;
bit128_t DECRYPTED_SECRET_KEY;

//Forward declaration of INTERFACE functions
void aes128_set_encrypt_key(bit128_t key); 
void aes128_set_decrypt_key(bit128_t key);
void initialize_rng(int seed); 
void initialize_mersenne_rng(int seed);
void rsa_set_key(EVP_PKEY *pkey);
EVP_PKEY *generate_rsa_key();
std::vector<unsigned char> rsa_encrypt_key(const bit128_t& plaintext);
bit128_t rsa_decrypt_key(const std::vector<unsigned char>& ciphertext);

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
        case AES128:    aes128_set_encrypt_key(SECRET_KEY); break;
        default:    break;
    }
}

void setParameters(SymmCipher cipher, uint64_t key_upper, uint64_t key_lower, int seed){
    CIPHER = cipher; 
    SECRET_KEY.init(key_upper, key_lower);      
    initialize_mersenne_rng(seed);

    switch(CIPHER){
        case AES128:    aes128_set_encrypt_key(SECRET_KEY); break;
        default:    break;
    }
}

void setParameters_XOR(uint64_t key_upper, uint64_t key_lower, int seed){
    CIPHER = SymmCipher::XOR; 
    SECRET_KEY.init(key_upper, key_lower);      
    initialize_mersenne_rng(seed);
}

// void encrypt_secret_key() {
//     std::cout << "SECRET_KEY for encryption: " << SECRET_KEY << std::endl;
//     std::vector<unsigned char> ciphertext = rsa_encrypt_key(SECRET_KEY);
//     // std::cout << "SECRET_KEY after encryption: " << std::endl;
//     // for (long unsigned int i = 0; i < ciphertext.size(); ++i) {
//     //     std::cout << (int)ciphertext[i] << " ";
//     // }
//     // std::cout << std::endl;
//     bit128_t decrypted = rsa_decrypt_key(ciphertext);
//     std::cout << "SECRET_KEY for decryption: " << decrypted << std::endl;
// }

void setRSAParameters() { 
    RSA_KEY = generate_rsa_key();
    rsa_set_key(RSA_KEY);
}

void encrypt_aes128_key() {
    ENCRYPTED_SECRET_KEY = rsa_encrypt_key(SECRET_KEY);
}

void decrypt_aes128_key() {
    DECRYPTED_SECRET_KEY = rsa_decrypt_key(ENCRYPTED_SECRET_KEY);
    aes128_set_decrypt_key(DECRYPTED_SECRET_KEY);
}

#endif
