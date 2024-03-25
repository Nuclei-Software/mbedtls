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

#include "zvksh.h"
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


#if defined(MBEDTLS_SM3_ALT)

// SM3 produces a 256 bits / 32 bytes hash.
#define SM3_HASH_BYTES (32)

#define MESSAGE_MAX_LENGTHS 5978
uint8_t input_ext[MESSAGE_MAX_LENGTHS];

typedef void (*hash_fn_t)(
    void* dest,
    const void* src,
    uint64_t length
);

struct sm3_routine {
    const char* name;
    // Minimum VLEN (bits) required to run this hash routine.
    size_t min_vlen;
    // Function pointer to the block hashing routine.
    hash_fn_t hash_fn;
};

// SM3 block hashing routines.
#define NUM_SM3_ROUTINES (3)
const struct sm3_routine sm3_routines[NUM_SM3_ROUTINES] = {
    {
        .name = "zvksh_sm3_encode_lmul1",
        .min_vlen = 256,
        .hash_fn = zvksh_sm3_encode_lmul1,
    },
    {
        .name = "zvksh_sm3_encode_lmul2",
        .min_vlen = 128,
        .hash_fn = zvksh_sm3_encode_lmul2,
    },
    {
        .name = "zvksh_sm3_encode_lmul4",
        .min_vlen = 64,
        .hash_fn = zvksh_sm3_encode_lmul4,
    },
};

// Pad input to block size, append delimiter and length.
static size_t
sm3_pad(uint8_t* output, const uint8_t* input, size_t len)
{
    const size_t blen = 8 * len;
    memcpy(output, input, len);
    output[len++] |= 0x80;

    // Calculate the padding size.
    // Message size is appended at the end of the last block,
    // take that into account.
    size_t padding = 64 - (len % 64);
    if (padding < sizeof(uint64_t)) {
        padding += 64;
    }

    bzero(output + len, padding);
    len += padding;

    uint32_t* ptr = (uint32_t*)(output + len - sizeof(uint64_t));

    *ptr = __builtin_bswap32(blen >> 32);
    *(++ptr) = __builtin_bswap32(blen & UINT32_MAX);

    return len;
}

void mbedtls_sm3_init( mbedtls_sm3_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_sm3_context ) );
}

void mbedtls_sm3_free( mbedtls_sm3_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sm3_context ) );
}

void mbedtls_sm3_clone( mbedtls_sm3_context *dst,
                        const mbedtls_sm3_context *src )
{
    *dst = *src;
}

/*
 * SM3 context setup
 */
int mbedtls_sm3_starts_ret( mbedtls_sm3_context *ctx )
{
    return( 0 );
}

/*
 * SM3 process buffer
 */
int mbedtls_sm3_update_ret( mbedtls_sm3_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    if (ilen > MESSAGE_MAX_LENGTHS - 64) {
      printf("Error: need more buffer!! ilen = %lu\r\n", ilen);
      return -1;
    }
    const size_t len = sm3_pad(input_ext, (uint8_t*)input, ilen);
    const struct sm3_routine* const routine = &sm3_routines[1];
    routine->hash_fn(ctx->buffer, input_ext, len);

    return( 0 );
}

/*
 * SM3 final digest
 */
int mbedtls_sm3_finish_ret( mbedtls_sm3_context *ctx,
                            unsigned char output[32] )
{
   for (int i = 0; i < 32; i++)
     output[i] = ctx->buffer[i];
   return( 0 );
}

#endif /* MBEDTLS_SM3_ALT */


#endif /* MBEDTLS_SM3_C */
