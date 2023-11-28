#ifndef _RSA_OPENSSL_INTERFACE_CPP
#define _RSA_OPENSSL_INTERFACE_CPP

#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <signal.h>
#include <string>
#include <vector>

#include "rsa_interface.h"

struct rsa_key ctx_rsa;

void rsa_set_key(EVP_PKEY *pkey) {
    rsa_init(ctx_rsa, pkey);
}

void rsa_init(struct rsa_key &ctx, EVP_PKEY *pkey) {
    if (!pkey) {
        throw std::runtime_error("rsa_init failed. Invalid pkey input.");
        return;
    }

    ctx.pkey = pkey;
}

EVP_PKEY *generate_rsa_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed.");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        throw std::runtime_error("EVP_PKEY_keygen_init failed.");
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, RSA_KEY_SIZE) <= 0) {
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed.");
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        throw std::runtime_error("EVP_PKEY_keygen failed.");
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    return pkey;
}

std::vector<unsigned char> rsa_encrypt_128(const bit128_t &plaintext, EVP_PKEY *public_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx) {
        throw std::runtime_error("Error creating EVP_PKEY_CTX for encryption");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error initializing encryption");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error setting RSA padding");
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext.value, sizeof(plaintext.value)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error determining encrypted key length");
    }

    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen, plaintext.value, sizeof(plaintext.value)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error encrypting key");
    }

    EVP_PKEY_CTX_free(ctx);
    return outbuf;
}

bit128_t rsa_decrypt_128(const std::vector<unsigned char> &ciphertext, EVP_PKEY *private_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        throw std::runtime_error("Error creating EVP_PKEY_CTX for decryption");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error initializing decryption");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error setting RSA padding for decryption");
    }

    size_t outlen = 256;

    unsigned char *decrypted_ptr = (unsigned char *)malloc(outlen);
    if (decrypted_ptr == NULL) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate memory for decrypted data");
    }

    if (EVP_PKEY_decrypt(ctx, decrypted_ptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        free(decrypted_ptr);
        EVP_PKEY_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error decrypting key");
    }

    bit128_t decrypted;
    memcpy(decrypted.value, decrypted_ptr, sizeof(decrypted.value));
    free(decrypted_ptr);

    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

std::vector<unsigned char> rsa_encrypt_key(const bit128_t &plaintext) {
    return rsa_encrypt_128(plaintext, ctx_rsa.pkey);
}

bit128_t rsa_decrypt_key(const std::vector<unsigned char> &ciphertext) {
    return rsa_decrypt_128(ciphertext, ctx_rsa.pkey);
}

void save_private_key(EVP_PKEY *pkey, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        throw std::runtime_error("save_private_key failed. Invalid filename" + std::string(filename) + ".");
        return;
    }

    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
}

void save_public_key(EVP_PKEY *pkey, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        throw std::runtime_error("save_public_key failed. Invalid filename" + std::string(filename) + ".");
        return;
    }

    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
}

// // Just for test
// int main () {
//     EVP_PKEY* pkey = generate_rsa_key();
//     std::cout << "pkey: " << pkey << std::endl;
//     save_private_key(pkey, "private_key.pem");
//     save_public_key(pkey, "public_key.pem");
//     return 0;
// }

#endif // _RSA_OPENSSL_INTERFACE_CPP