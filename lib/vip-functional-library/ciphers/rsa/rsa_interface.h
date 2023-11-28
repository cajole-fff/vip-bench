#ifndef _RSA_OPENSSL_INTERFACE_H
#define _RSA_OPENSSL_INTERFACE_H

#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <signal.h>
#include <string>
#include <vector>

#include "../../interface/parameters.h"

#define RSA_KEY_SIZE 2048

struct rsa_key {
    EVP_PKEY *pkey;
};

void rsa_set_key(EVP_PKEY *pkey);
void rsa_init(struct rsa_key &ctx, EVP_PKEY *pkey);
EVP_PKEY *generate_rsa_key();
// std::string rsa_encrypt(const std::string& plaintext, EVP_PKEY *public_key);
// std::string rsa_decrypt(const std::string& ciphertext, EVP_PKEY *private_key);
std::vector<unsigned char> rsa_encrypt_128(const bit128_t &plaintext, EVP_PKEY *public_key);
bit128_t rsa_decrypt_128(const std::vector<unsigned char> &ciphertext, EVP_PKEY *private_key);
std::vector<unsigned char> rsa_encrypt_key(const bit128_t &plaintext);
bit128_t rsa_decrypt_key(const std::vector<unsigned char> &ciphertext);
void save_private_key(EVP_PKEY *pkey, const char *filename);
void save_public_key(EVP_PKEY *pkey, const char *filename);

#endif // _RSA_OPENSSL_INTERFACE_H