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


#if defined(MBEDTLS_SM3_PROCESS_ALT)

#include "share/riscv-crypto-intrinsics.h"
#include "share/rvintrin.h"

// The block size in bytes
#define SM3_BLOCK_SIZE (16 * sizeof(uint32_t))

// Reverses the byte order of `V`
#define REVERSE_BYTES_32(V) (_rv32_grev((V), 0x18))

// Rotates `V` by `N` bits to the left
#define SM3_ROTATE_32(V, N) (_rv32_rol((V), (N)))

// The two permutation functions
#define SM3_P0(X) _sm3p0((X))
#define SM3_P1(X) _sm3p1((X))

// Expands state values and returns the result
#define SM3_EXPAND_STEP(W0, W3, W7, W10, W13)                                  \
  (SM3_P1((W0) ^ (W7) ^ SM3_ROTATE_32((W13), 15)) ^ SM3_ROTATE_32((W3), 7) ^   \
   (W10))

// Performs a compression step with permutation constant T, iteration I
// and expanded words W1 and W2
#define SM3_COMPRESS_STEP(I, W1, W2)                                           \
  {                                                                            \
    uint32_t t = (I) < 16 ? 0x79CC4519 : 0x7A879D8A;                           \
    uint32_t rot = SM3_ROTATE_32(x[0], 12);                                    \
    uint32_t ss1 = SM3_ROTATE_32(rot + x[4] + SM3_ROTATE_32(t, (I)), 7);       \
                                                                               \
    uint32_t tt1, tt2;                                                         \
    /* optimized out by the compiler */                                        \
    if ((I) < 16) {                                                            \
      tt1 = (x[0] ^ x[1] ^ x[2]) + x[3] + (ss1 ^ rot) + ((W1) ^ (W2));         \
      tt2 = (x[4] ^ x[5] ^ x[6]) + x[7] + ss1 + (W1);                          \
    } else {                                                                   \
      tt1 = ((x[0] & x[1]) | (x[0] & x[2]) | (x[1] & x[2])) + x[3] +           \
            (ss1 ^ rot) + ((W1) ^ (W2));                                       \
      tt2 = ((x[4] & x[5]) | (~x[4] & x[6])) + x[7] + ss1 + (W1);              \
    }                                                                          \
                                                                               \
    x[3] = x[2];                                                               \
    x[2] = SM3_ROTATE_32(x[1], 9);                                             \
    x[1] = x[0];                                                               \
    x[0] = tt1;                                                                \
    x[7] = x[6];                                                               \
    x[6] = SM3_ROTATE_32(x[5], 19);                                            \
    x[5] = x[4];                                                               \
    x[4] = SM3_P0(tt2);                                                        \
  }

// Compresses
void sm3_compress_block (
    uint32_t    H[ 8], //!< in,out - message block hash
    uint32_t    M[16]  //!< in - The message block to add to the hash
) {
  // The IV and iteration state
  uint32_t x[8];
  for (int i = 0; i < 8; ++i) {
    x[i] = H[i];
  }

  // `w` contains 16 of the expanded words.
  uint32_t w[16];
  for (int i = 0; i < 16; ++i) {
    w[i] = REVERSE_BYTES_32(M[i]);
  }

  // Compress first 12 words.
  for (int i = 0; i < 12; ++i) {
    SM3_COMPRESS_STEP(i, w[i], w[i + 4]);
  }
  // Compress and expand the remaining 4 words.
  for (int i = 0; i < 4; ++i) {
    w[i] =
        SM3_EXPAND_STEP(w[i], w[3 + i], w[7 + i], w[10 + i], w[(13 + i) % 16]);
    SM3_COMPRESS_STEP(i + 12, w[i + 12], w[i]);
  }

  // Rounds 16 to 64
  for (int j = 16; j < 64; j += 16) {
    // Expand and then compress the first 12 words as the remaining 4 need to be
    // handled differently in this implementation.
    for (int i = 0; i < 12; ++i) {
      w[4 + i] = SM3_EXPAND_STEP(w[4 + i], w[(7 + i) % 16], w[(11 + i) % 16],
                                 w[(14 + i) % 16], w[(1 + i) % 16]);
    }
    for (int i = 0; i < 12; ++i) {
      SM3_COMPRESS_STEP(i + j, w[i], w[i + 4]);
    }

    // Now expand and compress the remaining 4 words.
    for (int i = 0; i < 4; ++i) {
      w[i] = SM3_EXPAND_STEP(w[i], w[3 + i], w[7 + i], w[10 + i],
                             w[(13 + i) % 16]);
      SM3_COMPRESS_STEP(i + j + 12, w[i + 12], w[i]);
    }
  }

  // Xor `H` with `x`
  for (int i = 0; i < 8; ++i) {
    H[i] ^= x[i];
  }
}

/* SM3 Compression Function, CF */
int mbedtls_internal_sm3_process( mbedtls_sm3_context *ctx,
                                  const unsigned char data[64] )

{
    uint32_t *p = (uint32_t *)data;

    sm3_compress_block(ctx->state, p);

    return( 0 );
}


#endif /* MBEDTLS_SM3_PROCESS_ALT */


#endif /* MBEDTLS_SM3_C */
