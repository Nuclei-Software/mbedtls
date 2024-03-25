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

#include "zvknh.h"
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


#if defined(MBEDTLS_SHA512_PROCESS_ALT)

#define mbedtls_internal_sha512_process_c      mbedtls_internal_sha512_process

#define SHA512_BLOCK_SIZE       128

typedef void (*block_fn_t)(uint8_t* hash, const void* block);

struct sha_routine {
    const char* name;
    // Minimum VLEN (bits) required to run this hash routine.
    size_t min_vlen;
    // Function pointer to the block hashing routine.
    block_fn_t hash_fn;
};

// SHA-512 block hashing routines.
#define NUM_SHA512_ROUTINES (2)
const struct sha_routine sha512_routines[NUM_SHA512_ROUTINES] = {
    {
        .name = "sha512_block_lmul1",
        .min_vlen = 256,
        .hash_fn = sha512_block_lmul1,
    },
    {
        .name = "sha512_block_lmul2",
        .min_vlen = 128,
        .hash_fn = sha512_block_lmul2,
    },
};

struct sha_params {
    size_t digest_size;
    size_t block_size;
    size_t size_field_len;
    size_t initial_hash_size;
    const void* initial_hash;
    size_t num_routines;
    const struct sha_routine* routines;
};

const struct sha_params sha512_params = {
    .digest_size = SHA512_DIGEST_SIZE,
    .block_size = SHA512_BLOCK_SIZE,
    .size_field_len = 16,    // sizeof(uint128_t)
    .initial_hash = kSha512InitialHash,
    .initial_hash_size = sizeof(kSha512InitialHash),
    .num_routines = NUM_SHA512_ROUTINES,
    .routines = sha512_routines,
};

int mbedtls_internal_sha512_process_c( mbedtls_sha512_context *ctx,
                                       const unsigned char data[SHA512_BLOCK_SIZE] )

{

    uint64_t A[8];
    const struct sha_params* params = &sha512_params;

    A[0] = ctx->state[5];
    A[1] = ctx->state[4];
    A[2] = ctx->state[1];
    A[3] = ctx->state[0];
    A[4] = ctx->state[7];
    A[5] = ctx->state[6];
    A[6] = ctx->state[3];
    A[7] = ctx->state[2];

    const struct sha_routine* const routine = &params->routines[1];
    block_fn_t hash_block_fn = routine->hash_fn;
    hash_block_fn(A, data);

    ctx->state[5] = A[0];
    ctx->state[4] = A[1];
    ctx->state[1] = A[2];
    ctx->state[0] = A[3];
    ctx->state[7] = A[4];
    ctx->state[6] = A[5];
    ctx->state[3] = A[6];
    ctx->state[2] = A[7];

    return( 0 );
}

#endif /* MBEDTLS_SHA512_PROCESS_ALT */


#endif /* MBEDTLS_SHA512_C */
