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
#ifndef MBEDTLS_HASH_ALT_H
#define MBEDTLS_HASH_ALT_H

#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

/* mbedtls_md_context_t->md_ctx total[1] bit 0 : HASH algo */
#define MD_HASH_ALGO            0
#define MD_HMAC_ALGO            1

/* mbedtls_md_context_t->md_ctx total[1] bit [1,3] : HASH handle state */
#define MD_SEGMENT_DOWN         0
#define MD_HASH_DOWN            1
#define MD_OPAD                 2
#define MD_HMAC_FST_KEY         3
#define MD_HMAC_LST_KEY         4

/* HMAC key state */
#define HMAC_NONE_SET_KEY       0
#define HMAC_SET_FST_KEY        1
#define HMAC_SET_LST_KEY        2

#define MD_BUSY_TIMEOUT         ((uint32_t) 0x10011111)
#define MD_TIMEOUT_ERR          (-1)


int mbedtls_internal_md5_get_hmac_result(mbedtls_md5_context *ctx, unsigned char *out);
int mbedtls_internal_sha1_get_hmac_result(mbedtls_sha1_context *ctx, unsigned char *out);
int mbedtls_internal_sha256_get_hmac_result(mbedtls_sha256_context *ctx, unsigned char *out);
int mbedtls_internal_sha512_get_hmac_result(mbedtls_sha512_context *ctx, unsigned char *out);
int mbedtls_md5_update_key(mbedtls_md5_context *ctx, const unsigned char *key, size_t keylen, uint8_t keystate);
int mbedtls_sha1_update_key(mbedtls_sha1_context *ctx, const unsigned char *key, size_t keylen, uint8_t keystate);
int mbedtls_sha256_update_key(mbedtls_sha256_context *ctx, const unsigned char *key, size_t keylen, uint8_t keystate);
int mbedtls_sha512_update_key(mbedtls_sha512_context *ctx, const unsigned char *key, size_t keylen, uint8_t keystate);

#endif