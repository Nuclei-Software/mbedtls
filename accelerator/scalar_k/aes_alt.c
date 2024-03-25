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

#if defined(MBEDTLS_AES_C)

#include "api_aes.h"
#include <string.h>

// #define MBEDTLS_DEBUG

#include "mbedtls/aes.h"
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

#include <nmsis_bench.h>
BENCH_DECLARE_VAR();

//#define printf
/*
 * AES key schedule (encryption)
 */
#if defined(MBEDTLS_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    uint32_t *RK;

    ctx->rk_offset = 0;

    RK = ctx->buf + ctx->rk_offset;
   // BENCH_START(mbedtls_aes_setkey_enc);
    switch( keybits )
    {
        case 128:
          ctx->nr = 10;
          aes_128_enc_key_schedule(RK, (unsigned char *)key);
          break;
        case 192:
          ctx->nr = 12;
          aes_192_enc_key_schedule(RK, (unsigned char *)key);
          break;
        case 256:
          ctx->nr = 14;
          aes_256_enc_key_schedule(RK, (unsigned char *)key);
          break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
  //  BENCH_END(mbedtls_aes_setkey_enc);
    return 0;

}
#endif /* MBEDTLS_AES_SETKEY_ENC_ALT */

/*
 * AES key schedule (decryption)
 */
#if defined(MBEDTLS_AES_SETKEY_DEC_ALT)
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    uint32_t *RK;

    ctx->rk_offset = 0;
    RK = ctx->buf + ctx->rk_offset;
   // BENCH_START(mbedtls_aes_setkey_dec);
    switch( keybits )
    {
        case 128:
          ctx->nr = 10;
          aes_128_dec_key_schedule(RK, (unsigned char *)key);
          break;
        case 192:
          ctx->nr = 12;
          aes_192_dec_key_schedule(RK, (unsigned char *)key);
          break;
        case 256:
          ctx->nr = 14;
          aes_256_dec_key_schedule(RK, (unsigned char *)key);
          break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
   // BENCH_END(mbedtls_aes_setkey_dec);
    return 0;

}
#endif /* MBEDTLS_AES_SETKEY_DEC_ALT */
/*
 * AES-ECB block encryption
 */
#if defined(MBEDTLS_AES_ENCRYPT_ALT)
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    uint32_t *RK = ctx->buf + ctx->rk_offset;
    //BENCH_START(mbedtls_internal_aes_encrypt);
    switch( ctx->nr )
    {
        case 10:
        aes_128_ecb_encrypt(output, (unsigned char *)input, RK);
        break;
        case 12:
        aes_192_ecb_encrypt(output, (unsigned char *)input, RK);
        break;
        case 14:
        aes_256_ecb_encrypt(output, (unsigned char *)input, RK);
        break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
    //BENCH_END(mbedtls_internal_aes_encrypt);

    return( 0 );
}
#endif /* MBEDTLS_AES_ENCRYPT_ALT */

/*
 * AES-ECB block decryption
 */
#if defined(MBEDTLS_AES_DECRYPT_ALT)

int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    uint32_t *RK = ctx->buf + ctx->rk_offset;
  //  BENCH_START(mbedtls_internal_aes_decrypt);
    switch( ctx->nr )
    {
        case 10:
        aes_128_ecb_decrypt(output, (unsigned char *)input, RK);
        break;
        case 12:
        aes_192_ecb_decrypt(output, (unsigned char *)input, RK);
        break;
        case 14:
        aes_256_ecb_decrypt(output, (unsigned char *)input, RK);
        break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
  //  BENCH_END(mbedtls_internal_aes_decrypt);
    return( 0 );

}
#endif /* MBEDTLS_AES_DECRYPT_ALT */

#endif /* MBEDTLS_AES_C */
