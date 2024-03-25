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
#include "zvksed.h"
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

  RK[0] = __builtin_bswap32(*((uint32_t *)key));
  RK[1] = __builtin_bswap32(*((uint32_t *)key + 1));
  RK[2] = __builtin_bswap32(*((uint32_t *)key + 2));
  RK[3] = __builtin_bswap32(*((uint32_t *)key + 3));

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

  if( keybits != 128 )
    return MBEDTLS_ERR_SM4_INVALID_KEY_LENGTH;

  RK[0] = __builtin_bswap32(*((uint32_t *)key));
  RK[1] = __builtin_bswap32(*((uint32_t *)key + 1));
  RK[2] = __builtin_bswap32(*((uint32_t *)key + 2));
  RK[3] = __builtin_bswap32(*((uint32_t *)key + 3));

  return ( 0 );

}
#endif /* MBEDTLS_SM4_SETKEY_DEC_ALT */

/*
 * AES-ECB block encryption
 */
#if defined(MBEDTLS_SM4_CRYPT_ECB_ALT)

static void
sm4_encrypt_single(uint32_t *key, size_t len, uint32_t *input,
                   uint32_t *output, bool encrypt)
{
    if (encrypt) {
        zvksed_sm4_encode_vv(output, input, len, key);
    } else {
        zvksed_sm4_decode_vv(output, input, len, key);
    }
}

int mbedtls_sm4_crypt_ecb( mbedtls_sm4_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
  uint32_t *RK = ctx->rk;
  uint32_t input_b[4];
  uint32_t output_b[4];
  uint32_t *pres = output;

  input_b[0] = __builtin_bswap32(*((uint32_t *)input));
  input_b[1] = __builtin_bswap32(*((uint32_t *)input + 1));
  input_b[2] = __builtin_bswap32(*((uint32_t *)input + 2));
  input_b[3] = __builtin_bswap32(*((uint32_t *)input + 3));

  if ( mode == MBEDTLS_SM4_ENCRYPT ) {
     sm4_encrypt_single((uint32_t *)RK, 16, (uint32_t *)input_b, (uint32_t *)output_b, true);
  } else if ( mode == MBEDTLS_SM4_DECRYPT ) {
     sm4_encrypt_single((uint32_t *)RK, 16, (uint32_t *)input_b, (uint32_t *)output_b, false);
  } else {
     mbedtls_printf("%s wrong mode!\r\n", __func__);
     return ( -1 );
  }

  pres[0] = __builtin_bswap32(output_b[0]);
  pres[1] = __builtin_bswap32(output_b[1]);
  pres[2] = __builtin_bswap32(output_b[2]);
  pres[3] = __builtin_bswap32(output_b[3]);

  return( 0 );
}
#endif /* MBEDTLS_SM4_CRYPT_ECB_ALT */


#endif /* MBEDTLS_SM4_C */
