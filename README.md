# VIP-Bench Benchmark Suite - RSA / Key Exchange Extension
Implemented by: Fan Zhang, Peter Zhong ({zff, hpzhong} @umich.edu)

Based on the VIP-Bench: https://github.com/toddmaustin/vip-bench

## Introduction
This repository implements the VIP-bench support for key exchange protocol targeting the Sequestered Encryption (SE) architecture, which allows the user to define a symmetric key to be used by the SE unit to interpret and directly process the ciphertext data sent in by the user. 

## RSA with OpenSSL
For the symmetric key, we directly adopted the AES128 interface in the VIP-bench. For the asymmetric key, we implemented an RSA interface with OpenSSL in the functional library (``rsa_interface.cpp``). 

Functions to generate and store RSA keys:
* ``rsa_set_key(EVP_PKEY *pkey)``
* ``void rsa_init(struct rsa_key &ctx, EVP_PKEY *pkey)``
* ``EVP_PKEY *generate_rsa_key()``

Functions for RSA encryption and decryption:
* ``std::vector<unsigned char> rsa_encrypt_key(const bit128_t &plaintext)``
* ``bit128_t rsa_decrypt_key(const std::vector<unsigned char> &ciphertext)``


User Interface:
* ``VIP_Init``: Initialize the symmetric AES128 key and asymmetric RSA key
* ``VIP_ENC_AES128KEY``: Encrypt the AES128 key with RSA public key
* ``VIP_DEC_AES128KEY``: Decrypt the AES128 key with RSA private key


## Configuring Benchmarks to Include Key Exchange
Configuring a benchmark to work with the key exchange protocol is very straightforward. ``VIP_Init`` and `VIP_ENC_AES128KEY` needs to be inserted before any encrypted data structures used for the benchmark is initialized in order to set the initial symmetric encryption key and encrpty the symmetric key with the public key. ``VIP_DEC_AES128KEY`` needs to be inserted after the intializations of the encrypted data structures and before the actual benchmark starts to work on the data to decrypt the encrypted symmetric key and set the decrypted symmetric key to be used to interpret the encrypted data structures.

6 benchmarks from the original VIP-bench suite are configured as examples in this repository (``bitonic-sort``, ``boyer-moore-search``, ``bubble-sort``, ``distinctness``, ``filtered-query``, and ``shortest-path``). They are randomly selected from the original suite.

## Building and Running the VIP Benchmarks
The procedures to running the modified benchmarks is identical to that of an unmodified benchmark with the only exception that ``MODE`` should be set to ``enc`` to enable full encryption in benchmark runs.

```
make config-vip           # configure VIP-Bench to target the VIP-Bench functional library
cd <testbench-directory>  # enter the directory containing the testbench
make MODE=enc build       # Builds the benchmark
make MODE=enc test        # Runs the benchmark and validates its output
make MODE=enc clean       # Deleted all derived files
```

## References

L. Biernacki, M. Z. Demissie, K. B. Workneh, F. A. Andargie and T. Austin, "Sequestered Encryption: A Hardware Technique for Comprehensive Data Privacy," 2022 IEEE International Symposium on Secure and Private Execution Environment Design (SEED), Storrs, CT, USA, 2022, pp. 73-84, doi: 10.1109/SEED55351.2022.00014.

L. Biernacki et al., "VIP-Bench: A Benchmark Suite for Evaluating Privacy-Enhanced Computation Frameworks," 2021 International Symposium on Secure and Private Execution Environment Design (SEED), Washington, DC, USA, 2021, pp. 139-149, doi: 10.1109/SEED51797.2021.00026.

OpenSSL. https://www.openssl.org/
