#ifndef _RSA_OPENSSL_INTERFACE_CPP
#define _RSA_OPENSSL_INTERFACE_CPP

#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>

#include "rsa_interface.h"


struct rsa_key ctx_rsa;

void rsa_set_key(EVP_PKEY *pkey) {
    rsa_init(ctx_rsa, pkey);
}

void rsa_init(struct rsa_key ctx, EVP_PKEY *pkey) {
    if (!pkey) {
        throw std::runtime_error("rsa_init failed. Invalid pkey input.");
        return;
    }

    ctx.pkey = pkey;
}


EVP_PKEY *generate_rsa_key() {
    int bits = 2048; // Length of key in bits
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

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, bits) <= 0) {
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed.");
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    // Generate keys
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        throw std::runtime_error("EVP_PKEY_keygen failed.");
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    // Clean up
    EVP_PKEY_CTX_free(pkey_ctx);
    return pkey;
}


std::string rsa_encrypt(const std::string& plaintext, EVP_PKEY *public_key) {
    std::string ciphertext;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);

    if (!ctx) {
        // 错误处理
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    size_t outlen;
    // 首先调用一次以获取输出长度
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    ciphertext.assign(reinterpret_cast<char*>(outbuf.data()), outlen);
    EVP_PKEY_CTX_free(ctx);

    return ciphertext;
}

std::string rsa_decrypt(const std::string& ciphertext, EVP_PKEY *private_key) {
    std::string plaintext;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (!ctx) {
        // 错误处理
        return "";
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    size_t outlen;
    // 首先调用一次以获取输出长度
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_decrypt(ctx, outbuf.data(), &outlen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
        // 错误处理
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    plaintext.assign(reinterpret_cast<char*>(outbuf.data()), outlen);
    EVP_PKEY_CTX_free(ctx);

    return plaintext;
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