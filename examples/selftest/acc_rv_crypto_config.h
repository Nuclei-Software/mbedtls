/*
 *  Copyright (c) 2019 Nuclei Limited. All rights reserved.
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#ifndef MBEDTLS_RV_CRYPTO_ALT_CONFIG_H
#define MBEDTLS_RV_CRYPTO_ALT_CONFIG_H


/* AES supports the ECB/CBC/CTR/GCM/CCM modes. To use AES algorithm, turn on all
 * the following AES SETKEY enable macros and corresponding mode encryption/decryption
 * enable macros.
 * For example:
 * Turn on MBEDTLS_AES_SETKEY_ENC_ALT, MBEDTLS_AES_GCM_SETKEY_ALT and MBEDTLS_AES_GCM_CRYPT_ALT
 * to speed up AES GCM, otherwise not.
 */
/* AES ECB/CBC/CTR/GCM/CCM set encryption key(mbedtls-existed) */
#define MBEDTLS_AES_SETKEY_ENC_ALT
/* AES ECB/CBC set decryption key(mbedtls-existed) */
#define MBEDTLS_AES_SETKEY_DEC_ALT
/* AES ECB encryption(mbedtls-existed) */
#define MBEDTLS_AES_ENCRYPT_ALT
/* AES ECB decryption(mbedtls-existed) */
#define MBEDTLS_AES_DECRYPT_ALT

#define MBEDTLS_SHA256_PROCESS_ALT

#define MBEDTLS_SHA512_PROCESS_ALT

#if defined(MBEDTLS_ACC_SCALAR_K)
#define MBEDTLS_SM3_PROCESS_ALT
#endif

#if defined(MBEDTLS_ACC_VECTOR_K)
#define MBEDTLS_SM3_ALT
#endif

#define MBEDTLS_SM4_SETKEY_ENC_ALT

#define MBEDTLS_SM4_SETKEY_DEC_ALT

#define MBEDTLS_SM4_CRYPT_ECB_ALT

#endif
