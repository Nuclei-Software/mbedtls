# README for rsa8192_demo

## Introduction

This directory contains rsa8192_demo example files. This demo describes PKCS#1 encryption, decryption and signature verification for RSA8192.

RSA8192 can **only be accelerated with ACRYP engine**, a component of the Nuclei Crypto IP, by using **mbedtls_rsa_get_inv()** instead of **mbedtls_mpi_inv_mod()**. **Note** that the **RSA_8192** macro must be enabled in `acc_xlcrypto_config.h` when using ACRYP.

You can select the hardware acceleration of the corresponding algorithm by enabling the acceleration macros in `acc_xlcrypto_config.h`, compile and run the example using hardware engine or software implement. Please refer to `mbedtls/accelerator/xlcrypto/README.md` for more details.

## How to run this application

    # Assume that you can set up the Tools and Nuclei SDK environment
    # Assume that you use ns subsystem
    # cd to the cuttent directory
    cd examples/rsa8192_demo
    # Clean the application first
    make SOC=ns DOWNLOAD=ilm clean
    # Build and upload the application
    make SOC=ns DOWNLOAD=ilm upload

## Expected output as below

    Nuclei SDK Build Time: Dec 23 2022, 15:21:38
    Download Mode: ILM
    CPU Frequency 32000416 Hz
    RSA8192 key validation: passed
    PKCS#1 encryption : passed
    PKCS#1 decryption : passed
    PKCS#1 data sign  : passed
    PKCS#1 sig. verify: passed

    Executed 1 test suites

    [ All tests PASS ]
