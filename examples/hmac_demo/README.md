# README for hmac_demo

## Introduction

This directory contains hmac_demo example files.

This example describles two hmac process and outputs success or not. Each HMAC algorithm can be accelerated by **HASH** engine, you can choose one of the HMAC algorithm by modifying **HMAC_ALGO**, they are as follows:

- MBEDTLS_MD_MD5
- MBEDTLS_MD_SHA1
- MBEDTLS_MD_SHA224
- MBEDTLS_MD_SHA256
- MBEDTLS_MD_SHA384
- MBEDTLS_MD_SHA512

You can select the hardware acceleration of the corresponding algorithm by enabling the acceleration macros in `acc_config.h`, compile and run the example using hardware engine or software implement. Please refer to `mbedtls/README_Nuclei.md` for more details.

## How to run this application

    # Assume that you can set up the Tools and Nuclei SDK environment
    # cd to the cuttent directory
    cd examples/hmac_demo
    # Clean the application first
    make SOC=ns DOWNLOAD=sram clean
    # Build and upload the application
    make SOC=ns DOWNLOAD=sram upload

## Expected output as below

    Nuclei SDK Build Time: Dec  8 2022, 17:16:28
    Download Mode: SRAM
    CPU Frequency 32000389 Hz
    0 HMAC success
    1 HMAC success