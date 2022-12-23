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

You can select the hardware acceleration of the corresponding algorithm by enabling the acceleration macros in `acc_config.h`, compile and run the example and compare hardware and software benchmark result. Please refer to `mbedtls/README_Nuclei.md` for more details.

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

    MD5                      :  4194304 KiB/s, 1 cycles/byte
    SHA-1                    :  4194304 KiB/s, 2 cycles/byte
    SHA-256                  :  4194304 KiB/s, 2 cycles/byte
    SHA-512                  :  4194304 KiB/s, 2 cycles/byte
    3DES                     :  4194304 KiB/s, 9 cycles/byte
    DES                      :  4194304 KiB/s, 9 cycles/byte
    AES-CBC-128              :  4194304 KiB/s, 9 cycles/byte
    AES-CBC-192              :  4194304 KiB/s, 9 cycles/byte
    AES-CBC-256              :  4194304 KiB/s, 9 cycles/byte
    AES-GCM-128              :  4194304 KiB/s, 10 cycles/byte
    AES-GCM-192              :  4194304 KiB/s, 10 cycles/byte
    AES-GCM-256              :  4194304 KiB/s, 10 cycles/byte
    AES-CCM-128              :  4194304 KiB/s, 10 cycles/byte
    AES-CCM-192              :  4194304 KiB/s, 10 cycles/byte
    AES-CCM-256              :  4194304 KiB/s, 10 cycles/byte
    RSA-2048                 :  458   public/s
    RSA-2048                 :  5  private/s
    RSA-4096                 :  143   public/s
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
    ECDHE-secp256r1          :  16  full handshake/s
    ECDHE-secp256k1          :  16  full handshake/s
    ECDHE-brainpoolP256r1    :  16  full handshake/s
    ECDHE-secp224r1          :  18  full handshake/s
    ECDHE-secp224k1          :  23  full handshake/s
    ECDHE-secp192r1          :  28  full handshake/s
    ECDHE-secp192k1          :  28  full handshake/s
    ECDHE-x25519             :  24  full handshake/s
    ECDHE-x448               :  7  full handshake/s
