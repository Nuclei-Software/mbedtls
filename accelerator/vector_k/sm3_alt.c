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

#if defined(MBEDTLS_SM3_C)

// #define MBEDTLS_DEBUG

#include "mbedtls/sm3.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#include "api_sm3.h"

#if defined(MBEDTLS_SM3_PROCESS_ALT)
/* SM3 Compression Function, CF */
int mbedtls_internal_sm3_process( mbedtls_sm3_context *ctx,
                                  const unsigned char data[64] )
{
  sm3_transform_zvksh_zvkb(ctx->state, data, 1);

  return( 0 );
}

size_t mbedtls_internal_sm3_process_many( mbedtls_sm3_context *ctx,
                  const uint8_t *msg, size_t num )
{
   sm3_transform_zvksh_zvkb(ctx->state, msg, num);

   return( 0 );
}

#endif /* MBEDTLS_SM3_PROCESS_ALT */


#if defined(MBEDTLS_SM3_UPDATE_ALT)
int mbedtls_sm3_update_ret( mbedtls_sm3_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return( 0 );

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        if( ( ret = mbedtls_internal_sm3_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    if (ilen >= 64) {
      mbedtls_internal_sm3_process_many(ctx, input, ilen >> 6);
      input += ilen & 0xFFFFFFFFFFFFFFC0;
      ilen &= 0x3F;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );

    return( 0 );
}

#endif /* MBEDTLS_SM3_UPDATE_ALT */

#endif /* MBEDTLS_SM3_C */