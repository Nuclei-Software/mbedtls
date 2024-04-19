# README for benchmark

## Introduction

This directory contains benchmark example files.

This example describes benchmark testing process and exports benchmark result of each crypto algorithm. Each crypto algorithm can be accelerated by Nuclei hardware engine, they are as follows:

- MD5
- SHA1
- SHA224/SHA256
- SHA384/SHA512
- DES/3DES-CBC
- AES-CBC
- AES-GCM
- AES-CCM
- RSA2048/RSA4096
- ECDSA
- ECDH

You can select the hardware acceleration of the corresponding algorithm by enabling the acceleration macros in `acc_config.h`, compile and run the example and compare hardware and software benchmark result. Please refer to `mbedtls/accelerator/xlcrypto/README.md` for more details.

## How to run this application

    # Assume that you can set up the Tools and Nuclei SDK environment
    # cd to the cuttent directory
    cd examples/benchmark
    # Clean the application first
    make SOC=ns DOWNLOAD=sram clean
    # Build and upload the application
    make SOC=ns DOWNLOAD=sram upload

## Expected output as below:(HASH/CRYP with UDMA accelerated)

Nuclei SDK Build Time: Dec  8 2022, 18:01:33
Download Mode: SRAM
CPU Frequency 32000403 Hz

    MD5                      :  14562 KiB/s, 2 cycles/byte
    SHA-1                    :  13464 KiB/s, 2 cycles/byte
    SHA-256                  :  13145 KiB/s, 2 cycles/byte
    SHA-512                  :  10920 KiB/s, 2 cycles/byte
    3DES                     :  4058 KiB/s,  7 cycles/byte
    DES                      :  9832 KiB/s,  2 cycles/byte
    AES-CBC-128              :  13818 KiB/s, 2 cycles/byte
    AES-CBC-192              :  14690 KiB/s, 1 cycles/byte
    AES-CBC-256              :  14031 KiB/s, 2 cycles/byte
    AES-GCM-128              :  11385 KiB/s, 2 cycles/byte
    AES-GCM-192              :  11198 KiB/s, 2 cycles/byte
    AES-GCM-256              :  11160 KiB/s, 2 cycles/byte
    AES-CCM-128              :  9104 KiB/s,  3 cycles/byte
    AES-CCM-192              :  8441 KiB/s,  3 cycles/byte
    AES-CCM-256              :  7886 KiB/s,  3 cycles/byte
    RSA-2048                 :  442   public/s
    RSA-2048                 :  5  private/s
    RSA-4096                 :  136   public/s
    RSA-4096                 :  1  private/s
    ECDSA-secp521r1          :  12  sign/s
    ECDSA-brainpoolP512r1    :  12  sign/s
    ECDSA-secp384r1          :  23  sign/s
    ECDSA-brainpoolP384r1    :  23  sign/s
    ECDSA-secp256r1          :  52  sign/s
    ECDSA-secp256k1          :  51  sign/s
    ECDSA-brainpoolP256r1    :  50  sign/s
    ECDSA-secp224r1          :  58  sign/s
    ECDSA-secp224k1          :  64  sign/s
    ECDSA-secp192r1          :  82  sign/s
    ECDSA-secp192k1          :  81  sign/s
    ECDSA-secp521r1          :  5  verify/s
    ECDSA-brainpoolP512r1    :  6  verify/s
    ECDSA-secp384r1          :  11  verify/s
    ECDSA-brainpoolP384r1    :  11  verify/s
    ECDSA-secp256r1          :  28  verify/s
    ECDSA-secp256k1          :  26  verify/s
    ECDSA-brainpoolP256r1    :  26  verify/s
    ECDSA-secp224r1          :  31  verify/s
    ECDSA-secp224k1          :  36  verify/s
    ECDSA-secp192r1          :  45  verify/s
    ECDSA-secp192k1          :  44  verify/s
    ECDHE-secp521r1          :  3  full handshake/s
    ECDHE-brainpoolP512r1    :  3  full handshake/s
    ECDHE-secp384r1          :  6  full handshake/s
    ECDHE-brainpoolP384r1    :  6  full handshake/s
    ECDHE-secp256r1          :  15  full handshake/s
    ECDHE-secp256k1          :  15  full handshake/s
    ECDHE-brainpoolP256r1    :  15  full handshake/s
    ECDHE-secp224r1          :  17  full handshake/s
    ECDHE-secp224k1          :  21  full handshake/s
    ECDHE-secp192r1          :  27  full handshake/s
    ECDHE-secp192k1          :  27  full handshake/s
    ECDHE-x25519             :  22  full handshake/s
    ECDHE-x448               :  6  full handshake/s
