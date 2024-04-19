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

#if defined(MBEDTLS_SHA512_C)

// #define MBEDTLS_DEBUG

#include "mbedtls/sha512.h"
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

#include "api_sha512.h"

#if defined(MBEDTLS_SHA512_PROCESS_ALT)

#define mbedtls_internal_sha512_process_many_c mbedtls_internal_sha512_process_many
#define mbedtls_internal_sha512_process_c      mbedtls_internal_sha512_process

#define SHA512_BLOCK_SIZE       128

int mbedtls_internal_sha512_process_c( mbedtls_sha512_context *ctx,
                                       const unsigned char data[SHA512_BLOCK_SIZE] )
{
    sha512_transform_zvknhb_zvkb(ctx->state, data, 1);
    return( 0 );
}

static size_t mbedtls_internal_sha512_process_many( mbedtls_sha512_context *ctx,
                  const uint8_t *msg, size_t len )
{
    sha512_transform_zvknhb_zvkb(ctx->state, msg, len);
    return( 0 );
}

#endif /* MBEDTLS_SHA512_PROCESS_ALT */

#if defined(MBEDTLS_SHA512_UPDATE_ALT)
int mbedtls_sha512_update( mbedtls_sha512_context *ctx,
                               const unsigned char *input,
                               size_t ilen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t fill;
    unsigned int left;

    if( ilen == 0 )
        return( 0 );

    left = (unsigned int) (ctx->total[0] & 0x7F);
    fill = SHA512_BLOCK_SIZE - left;

    ctx->total[0] += (uint64_t) ilen;

    if( ctx->total[0] < (uint64_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );

        if( ( ret = mbedtls_internal_sha512_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    if ( ilen >= SHA512_BLOCK_SIZE )
    {
        mbedtls_internal_sha512_process_many( ctx, input, ilen >> 7);

        input += ilen & 0xFFFFFFFFFFFFFF80;
        ilen &= 0x7F;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );

    return( 0 );
}
#endif


#endif /* MBEDTLS_SHA512_C */
