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

#include "common.h"

#if defined(MBEDTLS_SM4_C)

#include <string.h>
#include <stdbool.h>
// #define MBEDTLS_DEBUG

#include "mbedtls/sm4.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_PADLOCK_C)
#include "padlock.h"
#endif
#if defined(MBEDTLS_AESNI_C)
#include "aesni.h"
#endif

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#include "api_sm4.h"

/*
 * AES key schedule (encryption)
 */
#if defined(MBEDTLS_SM4_SETKEY_ENC_ALT)
int mbedtls_sm4_setkey_enc( mbedtls_sm4_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits )
{
  uint32_t *RK = ctx->rk;
  uint32_t rkey_dec[SM4_RKEY_WORDS];

  if( keybits != 128 )
     return MBEDTLS_ERR_SM4_INVALID_KEY_LENGTH;

    sm4_expandkey_zvksed_zvkb(key, RK, rkey_dec);

  return ( 0 );
}
#endif /* MBEDTLS_SM4_SETKEY_ENC_ALT */

/*
 * AES key schedule (decryption)
 */
#if defined(MBEDTLS_SM4_SETKEY_DEC_ALT)
int mbedtls_sm4_setkey_dec( mbedtls_sm4_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits )
{
  uint32_t *RK = ctx->rk;
  uint32_t rkey_enc[SM4_RKEY_WORDS];

  if( keybits != 128 )
    return MBEDTLS_ERR_SM4_INVALID_KEY_LENGTH;

    sm4_expandkey_zvksed_zvkb(key, rkey_enc, RK);

  return ( 0 );
}
#endif /* MBEDTLS_SM4_SETKEY_DEC_ALT */

/*
 * AES-ECB block encryption
 */
#if defined(MBEDTLS_SM4_CRYPT_ECB_ALT)

int mbedtls_sm4_crypt_ecb( mbedtls_sm4_context *ctx,
                    int mode,
                    const unsigned char input[SM4_BLOCK_SIZE],
                    unsigned char output[SM4_BLOCK_SIZE] )
{
  uint32_t *RK = ctx->rk;

  sm4_crypt_zvksed_zvkb(RK, input, output);

  return( 0 );
}
#endif /* MBEDTLS_SM4_CRYPT_ECB_ALT */


#endif /* MBEDTLS_SM4_C */
