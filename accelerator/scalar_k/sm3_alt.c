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
#include "api_sm3.h"
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


#if defined(MBEDTLS_SM3_PROCESS_ALT)

/* SM3 Compression Function, CF */
int mbedtls_internal_sm3_process( mbedtls_sm3_context *ctx,
                                  const unsigned char data[64] )

{
    uint32_t A[24];
    unsigned long i;

    for( i = 0; i < 8; i++ )
        A[i] = ctx->state[i];
    for (i = 0; i < 16; i++) {
        A[8 + i] = (uint32_t)*((uint32_t *)(data + 4 * i));
    }

    sm3_compress(A);

    for( i = 0; i < 8; i++ )
        ctx->state[i] = A[i];

    return( 0 );
}


#endif /* MBEDTLS_SM3_PROCESS_ALT */


#endif /* MBEDTLS_SM3_C */
