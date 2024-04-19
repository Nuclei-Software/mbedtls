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


#define MBEDTLS_AES_SETKEY_ENC_ALT
#define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_AES_ENCRYPT_ALT
#define MBEDTLS_AES_DECRYPT_ALT

#if defined(MBEDTLS_ACC_VECTOR_K)
#define MBEDTLS_AES_CBC_ALT
#endif

#define MBEDTLS_SHA256_PROCESS_ALT
#define MBEDTLS_SHA512_PROCESS_ALT

#if defined(MBEDTLS_ACC_VECTOR_K)
#define MBEDTLS_SHA256_UPDATE_ALT
#define MBEDTLS_SHA512_UPDATE_ALT
#endif

#define MBEDTLS_SM3_PROCESS_ALT

#if defined(MBEDTLS_ACC_VECTOR_K)
#define MBEDTLS_SM3_UPDATE_ALT
#endif

#define MBEDTLS_SM4_SETKEY_ENC_ALT
#define MBEDTLS_SM4_SETKEY_DEC_ALT
#define MBEDTLS_SM4_CRYPT_ECB_ALT

#endif