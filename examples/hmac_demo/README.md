# README for hmac_demo

## Introduction

This directory contains hmac_demo example files. This example describles two hmac process and outputs success or not.

HMAC algorithm can **only be accelerated with HASH engine**, a component of the Nuclei Crypto IP. When using the HASH engine to accelerate the HMAC algorithm, the macros related to **HMAC** in `acc_xlcrypto_config.h` must be enabled.

This example will run the following HMAC algorithms:

- MBEDTLS_MD_MD5
- MBEDTLS_MD_SHA1
- MBEDTLS_MD_SHA224
- MBEDTLS_MD_SHA256
- MBEDTLS_MD_SHA384
- MBEDTLS_MD_SHA512

You can select the hardware acceleration of the corresponding algorithm by enabling the acceleration macros in `acc_xlcrypto_config.h`, compile and run the example using hardware engine or software implement. Please refer to `mbedtls/accelerator/xlcrypto/README.md` for more details.

## How to run this application

    # Assume that you can set up the Tools and Nuclei SDK environment
    # Assume that you use ns subsystem
    # cd to the cuttent directory
    cd examples/hmac_demo
    # Clean the application first
    make SOC=ns DOWNLOAD=ilm clean
    # Build and upload the application
    make SOC=ns DOWNLOAD=ilm upload

## Expected output as below

    Nuclei SDK Build Time: May 23 2024, 16:07:21
    Download Mode: ILM
    CPU Frequency 30000031 Hz
    CPU HartID: 0
    Testing MD algorithm: MD5
    0 HMAC success
    1 HMAC success
    Testing MD algorithm: SHA1
    0 HMAC success
    1 HMAC success
    Testing MD algorithm: SHA224
    0 HMAC success
    1 HMAC success
    Testing MD algorithm: SHA256
    0 HMAC success
    1 HMAC success
    Testing MD algorithm: SHA384
    0 HMAC success
    1 HMAC success
    Testing MD algorithm: SHA512
    0 HMAC success
    1 HMAC success