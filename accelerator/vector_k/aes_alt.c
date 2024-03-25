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

#include "zvkned.h"
#include "vlen-bits.h"
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

typedef uint64_t (aes_transform_t)(
   void* dest,
   const void* src,
   uint64_t n,
   const uint32_t* expanded_key
);

enum TransformDirection {
    kEncode,
    kDecode,
};

struct aes_routine {
    const char* name;
    const char* descr;
    aes_transform_t* fn;
    size_t keylen;
    // Minimum VLEN (in bits) required to.
    size_t min_vlen;
    enum TransformDirection direction;
};

static const struct aes_routine kAESRoutines_AES128_enc[] = {
    // AES-128 encode
    {
        .name = "zvkned_aes128_encode_vs_lmul1",
        .descr = "AES-128 encode, vs variant, LMUL=1",
        .fn = &zvkned_aes128_encode_vs_lmul1,
        .keylen = 128,
        .min_vlen = 128,
        .direction = kEncode,
    },
    {
        .name = "zvkned_aes128_encode_vs_lmul2",
        .descr = "AES-128 encode, vs variant, LMUL=2",
        .fn = &zvkned_aes128_encode_vs_lmul2,
        .keylen = 128,
        .min_vlen = 64,
        .direction = kEncode,
    },
    {
        .name = "zvkned_aes128_encode_vs_lmul4",
        .descr = "AES-128 encode, vs variant, LMUL=4",
        .fn = &zvkned_aes128_encode_vs_lmul4,
        .keylen = 128,
        .min_vlen = 32,
        .direction = kEncode,
    },

    {
        .name = "zvkned_aes128_encode_vv_lmul1",
        .descr = "AES-128 encode, vv variant, LMUL=1",
        .fn = &zvkned_aes128_encode_vv_lmul1,
        .keylen = 128,
        .min_vlen = 128,
        .direction = kEncode,
    },
};

static const struct aes_routine kAESRoutines_AES128_dec[] = {
    // AES-128 decode
    {
        .name = "zvkned_aes128_decode_vs_lmul1",
        .descr = "AES-128 decode, vs variant, LMUL=1",
        .fn = &zvkned_aes128_decode_vs_lmul1,
        .keylen = 128,
        .min_vlen = 128,
        .direction = kDecode,
    },
    {
        .name = "zvkned_aes128_decode_vs_lmul2",
        .descr = "AES-128 decode, vs variant, LMUL=2",
        .fn = &zvkned_aes128_decode_vs_lmul2,
        .keylen = 128,
        .min_vlen = 64,
        .direction = kDecode,
    },

    {
        .name = "zvkned_aes128_decode_vv_lmul1",
        .descr = "AES-128 decode, vv variant, LMUL=1",
        .fn = &zvkned_aes128_decode_vv_lmul1,
        .keylen = 128,
        .min_vlen = 128,
        .direction = kDecode,
    },
};

static const struct aes_routine kAESRoutines_AES256_enc[] = {
    // AES-256 encode
    {
        .name = "zvkned_aes256_encode_vs_lmul1",
        .descr = "AES-256 encode, vs variant, LMUL=1",
        .fn = &zvkned_aes256_encode_vs_lmul1,
        .keylen = 256,
        .min_vlen = 128,
        .direction = kEncode,
    },
    {
        .name = "zvkned_aes256_encode_vs_lmul2",
        .descr = "AES-256 encode, vs variant, LMUL=2",
        .fn = &zvkned_aes256_encode_vs_lmul2,
        .keylen = 256,
        .min_vlen = 64,
        .direction = kEncode,
    },
    {
        .name = "zvkned_aes256_encode_vs_lmul4",
        .descr = "AES-256 encode, vs variant, LMUL=4",
        .fn = &zvkned_aes256_encode_vs_lmul4,
        .keylen = 256,
        .min_vlen = 32,
        .direction = kEncode,
    },

    {
        .name = "zvkned_aes256_encode_vv_lmul1",
        .descr = "AES-256 encode, vv variant, LMUL=1",
        .fn = &zvkned_aes256_encode_vv_lmul1,
        .keylen = 256,
        .min_vlen = 128,
        .direction = kEncode,
    },
};

static const struct aes_routine kAESRoutines_AES256_dec[] = {
    // AES-256 decode
    {
        .name = "zvkned_aes256_decode_vs_lmul1",
        .descr = "AES-256 decode, vs variant, LMUL=1",
        .fn = &zvkned_aes256_decode_vs_lmul1,
        .keylen = 256,
        .min_vlen = 128,
        .direction = kDecode,
    },
    {
        .name = "zvkned_aes256_decode_vs_lmul2",
        .descr = "AES-256 decode, vs variant, LMUL=2",
        .fn = &zvkned_aes256_decode_vs_lmul2,
        .keylen = 256,
        .min_vlen = 64,
        .direction = kDecode,
    },

    {
        .name = "zvkned_aes256_decode_vv_lmul1",
        .descr = "AES-256 decode, vv variant, LMUL=1",
        .fn = &zvkned_aes256_decode_vv_lmul1,
        .keylen = 256,
        .min_vlen = 128,
        .direction = kDecode,
    },
};

struct expanded_key {
    // 240 bytes for AES-256, less needed for AES-128.
    // Using uint32_t guarantees alignment.
    uint32_t expanded[60];
    //
    size_t keylen;
};

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
 //   BENCH_START(mbedtls_aes_setkey_enc);
    switch( keybits )
    {
        case 128:
          ctx->nr = 10;
          // 128b -> 11*128b, 176B, 44 uin32_t
          zvkned_aes128_expand_key(RK, key);
          break;
        case 192:
          return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
        case 256:
          ctx->nr = 14;
          // 256b -> 15*128b, 240B, 60 uint32_t
          zvkned_aes256_expand_key(RK, key);
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
  //  BENCH_START(mbedtls_aes_setkey_dec);
    switch( keybits )
    {
        case 128:
          ctx->nr = 10;
          // 128b -> 11*128b, 176B, 44 uin32_t
          zvkned_aes128_expand_key(RK, key);
          break;
        case 192:
          return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
        case 256:
          ctx->nr = 14;
          // 256b -> 15*128b, 240B, 60 uint32_t
          zvkned_aes256_expand_key(RK, key);
          break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
  //  BENCH_END(mbedtls_aes_setkey_dec);
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
	  const struct aes_routine* routine;
   // BENCH_START(mbedtls_internal_aes_encrypt);
    switch( ctx->nr )
    {
        case 10:
          routine = &kAESRoutines_AES128_enc[0];
          routine->fn(output, input, 16, RK);
          break;
        case 14:
          routine = &kAESRoutines_AES256_enc[0];
          routine->fn(output, input, 16, RK);
          break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
   // BENCH_END(mbedtls_internal_aes_encrypt);

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
    const struct aes_routine* routine;
 //   BENCH_START(mbedtls_internal_aes_decrypt);
    switch( ctx->nr )
    {
        case 10:
          routine = &kAESRoutines_AES128_dec[0];
          routine->fn(output, input, 16, RK);
          break;
        case 14:
          routine = &kAESRoutines_AES256_dec[0];
          routine->fn(output, input, 16, RK);
          break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
 //   BENCH_END(mbedtls_internal_aes_decrypt);
    return( 0 );

}
#endif /* MBEDTLS_AES_DECRYPT_ALT */

#endif /* MBEDTLS_AES_C */
