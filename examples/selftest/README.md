# README for selftest

## Introduction

This directory contains selftest example files.

This example describes each crypto algorithm selftest process, you can use this example to verify the correctness of the hardware acceleration of the crypto algorithm. The crypto algorithms are as follows:

- MD5
- SHA1
- SHA224/SHA256
- SHA384/SHA512
- DES/3DES-ECB
- DES/3DES-CBC
- AES-ECB
- AES-CBC
- AES-CTR
- AES-GCM
- AES-CCM
- BIGNUM-ADD
- BIGNUM-SUB
- BIGNUM-MOD
- BIGNUM-MUL
- BIGNUM-INVMOD
- BIGNUM-MEXP
- RSA PKCS#1
- ECC SHORT WEIERSTRASS
- ECC MONTGOMERY

You can select the hardware acceleration of the corresponding algorithm by enabling the acceleration macros in `acc_config.h`, compile and run the example using hardware engine or software implement. Please refer to `mbedtls/README_Nuclei.md` for more details.

## How to run this application

    # Assume that you can set up the Tools and Nuclei SDK environment
    # cd to the cuttent directory
    cd examples/selftest
    # Clean the application first
    make SOC=ns DOWNLOAD=sram clean
    # Build and upload the application
    make SOC=ns DOWNLOAD=sram upload

## Expected output as below:

    Nuclei SDK Build Time: Dec  7 2022, 21:27:22
    Download Mode: SRAM
    CPU Frequency 32000403 Hz
    CALLOC(0): passed (distinct non-null)
    CALLOC(1): passed
    CALLOC(1 again): passed

    MD5 test #1: passed
    MD5 test #2: passed
    MD5 test #3: passed
    MD5 test #4: passed
    MD5 test #5: passed
    MD5 test #6: passed
    MD5 test #7: passed

    SHA-1 test #1: passed
    SHA-1 test #2: passed
    SHA-1 test #3: passed

    SHA-224 test #1: passed
    SHA-224 test #2: passed
    SHA-224 test #3: passed
    SHA-256 test #1: passed
    SHA-256 test #2: passed
    SHA-256 test #3: passed

    SHA-384 test #1: passed
    SHA-384 test #2: passed
    SHA-384 test #3: passed
    SHA-512 test #1: passed
    SHA-512 test #2: passed
    SHA-512 test #3: passed

    DES -ECB- 56 (dec): passed
    DES -ECB- 56 (enc): passed
    DES3-ECB-112 (dec): passed
    DES3-ECB-112 (enc): passed
    DES3-ECB-168 (dec): passed
    DES3-ECB-168 (enc): passed

    DES -CBC- 56 (dec): passed
    DES -CBC- 56 (enc): passed
    DES3-CBC-112 (dec): passed
    DES3-CBC-112 (enc): passed
    DES3-CBC-168 (dec): passed
    DES3-CBC-168 (enc): passed

    AES-ECB-128 (dec): passed
    AES-ECB-128 (enc): passed
    AES-ECB-192 (dec): passed
    AES-ECB-192 (enc): passed
    AES-ECB-256 (dec): passed
    AES-ECB-256 (enc): passed

    AES-CBC-128 (dec): passed
    AES-CBC-128 (enc): passed
    AES-CBC-192 (dec): passed
    AES-CBC-192 (enc): passed
    AES-CBC-256 (dec): passed
    AES-CBC-256 (enc): passed

    AES-CFB128-128 (dec): passed
    AES-CFB128-128 (enc): passed
    AES-CFB128-192 (dec): passed
    AES-CFB128-192 (enc): passed
    AES-CFB128-256 (dec): passed
    AES-CFB128-256 (enc): passed

    AES-OFB-128 (dec): passed
    AES-OFB-128 (enc): passed
    AES-OFB-192 (dec): passed
    AES-OFB-192 (enc): passed
    AES-OFB-256 (dec): passed
    AES-OFB-256 (enc): passed

    AES-CTR-128 (dec): passed
    AES-CTR-128 (enc): passed
    AES-CTR-128 (dec): passed
    AES-CTR-128 (enc): passed
    AES-CTR-128 (dec): passed
    AES-CTR-128 (enc): passed

    AES-GCM-128 #0 (enc): passed
    AES-GCM-128 #0 (dec): passed
    AES-GCM-128 #1 (enc): passed
    AES-GCM-128 #1 (dec): passed
    AES-GCM-128 #2 (enc): passed
    AES-GCM-128 #2 (dec): passed
    AES-GCM-128 #3 (enc): passed
    AES-GCM-128 #3 (dec): passed
    AES-GCM-192 #0 (enc): passed
    AES-GCM-192 #0 (dec): passed
    AES-GCM-192 #1 (enc): passed
    AES-GCM-192 #1 (dec): passed
    AES-GCM-192 #2 (enc): passed
    AES-GCM-192 #2 (dec): passed
    AES-GCM-192 #3 (enc): passed
    AES-GCM-192 #3 (dec): passed
    AES-GCM-256 #0 (enc): passed
    AES-GCM-256 #0 (dec): passed
    AES-GCM-256 #1 (enc): passed
    AES-GCM-256 #1 (dec): passed
    AES-GCM-256 #2 (enc): passed
    AES-GCM-256 #2 (dec): passed
    AES-GCM-256 #3 (enc): passed
    AES-GCM-256 #3 (dec): passed

    CCM-AES #1: passed
    CCM-AES #2: passed
    CCM-AES #3: passed

    MPI test #1 (add_mpi): passed
    MPI test #2 (add_int): passed
    MPI test #3 (sub_mpi): passed
    MPI test #4 (sub_int): passed
    MPI test #5 (mod_mpi): passed

    MPI test #6 (mul_mpi): passed
    MPI test #7 (exp_mod): passed
    MPI test #8 (inv_mod): passed

    RSA key validation: passed
    PKCS#1 encryption : passed
    PKCS#1 decryption : passed
    PKCS#1 data sign  : passed
    PKCS#1 sig. verify: passed

    ECP SW test #1 (constant op_count, base point G): passed
    ECP SW test #2 (constant op_count, other point): passed
    ECP Montgomery test (constant op_count): passed

    Executed 12 test suites

    [ All tests PASS ]