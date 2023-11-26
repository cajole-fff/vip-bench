#ifndef _RSA_OPENSSL_INTERFACE_H
#define _RSA_OPENSSL_INTERFACE_H

#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>

#include "rsani.h"

struct rsa_key {
    EVP_PKEY *pkey;
};

void rsa_set_key(EVP_PKEY *pkey);
void rsa_init(struct rsa_key ctx, EVP_PKEY *pkey);
EVP_PKEY *generate_rsa_key();
std::string rsa_encrypt(const std::string& plaintext, EVP_PKEY *public_key);
std::string rsa_decrypt(const std::string& ciphertext, EVP_PKEY *private_key);
void save_private_key(EVP_PKEY *pkey, const char *filename);
void save_public_key(EVP_PKEY *pkey, const char *filename);

#endif // _RSA_OPENSSL_INTERFACE_H