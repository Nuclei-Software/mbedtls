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

#include "api_aes.h"
#include <string.h>

// #define MBEDTLS_DEBUG

#include "mbedtls/sm4.h"
#include "api_sm4.h"
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

/*
 * AES key schedule (encryption)
 */
#if defined(MBEDTLS_SM4_SETKEY_ENC_ALT)
int mbedtls_sm4_setkey_enc( mbedtls_sm4_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits )
{
    uint32_t *RK = ctx->rk;

    if( keybits != 128 )
        return MBEDTLS_ERR_SM4_INVALID_KEY_LENGTH;
    sm4_key_schedule_enc(RK, (uint8_t *)key);

    return 0;

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

    if( keybits != 128 )
        return MBEDTLS_ERR_SM4_INVALID_KEY_LENGTH;
    sm4_key_schedule_dec(RK, (uint8_t *)key);
    return 0;

}
#endif /* MBEDTLS_SM4_SETKEY_DEC_ALT */

/*
 * AES-ECB block encryption
 */
#if defined(MBEDTLS_SM4_CRYPT_ECB_ALT)
int mbedtls_sm4_crypt_ecb( mbedtls_sm4_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
  uint32_t *RK = ctx->rk;
  ( (void) mode );                        // parameter not used

  sm4_block_enc_dec(output, (uint8_t *)input, RK);

  return( 0 );
}
#endif /* MBEDTLS_SM4_CRYPT_ECB_ALT */


#endif /* MBEDTLS_SM4_C */
