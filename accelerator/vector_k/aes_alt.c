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

#include <string.h>

// #define MBEDTLS_DEBUG

#include "api_aes.h"

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

/* vector K don't support aes-192 key */
#define AES_KEY_USE_VECTOR_K_ALT 0

#if defined(MBEDTLS_AES_SETKEY_ENC_ALT) && defined(MBEDTLS_AES_SETKEY_DEC_ALT)
/**
 * aes_expandkey - Expands the AES key as described in FIPS-197
 * @ctx:	The location where the computed key will be stored.
 * @in_key:	The supplied key.
 * @key_len:	The length of the supplied key.
 *
 * Returns 0 on success. The function fails only if an invalid key size (or
 * pointer) is supplied.
 * The expanded key size is 240 bytes (max of 14 rounds with a unique 16 bytes
 * key schedule plus a 16 bytes key which is used before the first round).
 * The decryption key is prepared for the "Equivalent Inverse Cipher" as
 * described in FIPS-197. The first slot (16 bytes) of each key (enc or dec) is
 * for the initial combination, the second slot for the first round and so on.
 */

static volatile const uint8_t aes_sbox[] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
  return (word >> (shift & 31)) | (word << ((-shift) & 31));
}

static uint32_t subw(uint32_t in)
{
	return (aes_sbox[in & 0xff]) ^
	       (aes_sbox[(in >>  8) & 0xff] <<  8) ^
	       (aes_sbox[(in >> 16) & 0xff] << 16) ^
	       (aes_sbox[(in >> 24) & 0xff] << 24);
}

static uint32_t mul_by_x(uint32_t w)
{
	uint32_t x = w & 0x7f7f7f7f;
	uint32_t y = w & 0x80808080;

	/* multiply by polynomial 'x' (0b10) in GF(2^8) */
	return (x << 1) ^ (y >> 7) * 0x1b;
}

static uint32_t mul_by_x2(uint32_t w)
{
	uint32_t x = w & 0x3f3f3f3f;
	uint32_t y = w & 0x80808080;
	uint32_t z = w & 0x40404040;

	/* multiply by polynomial 'x^2' (0b100) in GF(2^8) */
	return (x << 2) ^ (y >> 7) * 0x36 ^ (z >> 6) * 0x1b;
}

static uint32_t mix_columns(uint32_t x)
{
	/*
	 * Perform the following matrix multiplication in GF(2^8)
	 *
	 * | 0x2 0x3 0x1 0x1 |   | x[0] |
	 * | 0x1 0x2 0x3 0x1 |   | x[1] |
	 * | 0x1 0x1 0x2 0x3 | x | x[2] |
	 * | 0x3 0x1 0x1 0x2 |   | x[3] |
	 */
	uint32_t y = mul_by_x(x) ^ ror32(x, 16);

	return y ^ ror32(x ^ y, 8);
}

static uint32_t inv_mix_columns(uint32_t x)
{
	/*
	 * Perform the following matrix multiplication in GF(2^8)
	 *
	 * | 0xe 0xb 0xd 0x9 |   | x[0] |
	 * | 0x9 0xe 0xb 0xd |   | x[1] |
	 * | 0xd 0x9 0xe 0xb | x | x[2] |
	 * | 0xb 0xd 0x9 0xe |   | x[3] |
	 *
	 * which can conveniently be reduced to
	 *
	 * | 0x2 0x3 0x1 0x1 |   | 0x5 0x0 0x4 0x0 |   | x[0] |
	 * | 0x1 0x2 0x3 0x1 |   | 0x0 0x5 0x0 0x4 |   | x[1] |
	 * | 0x1 0x1 0x2 0x3 | x | 0x4 0x0 0x5 0x0 | x | x[2] |
	 * | 0x3 0x1 0x1 0x2 |   | 0x0 0x4 0x0 0x5 |   | x[3] |
	 */
	uint32_t y = mul_by_x2(x);

	return mix_columns(x ^ y ^ ror32(y, 16));
}

int aes_expandkey(mbedtls_aes_context *ctx, const unsigned char *in_key,
		  unsigned int key_len)
{
	uint32_t kwords = key_len / sizeof(uint32_t);
	uint32_t rc, i, j;
	uint32_t *RK = ctx->buf + ctx->rk_offset;

	ctx->key_length = key_len;

	for (i = 0; i < kwords; i++)
		RK[i] = MBEDTLS_GET_UINT32_LE(in_key, i << 2);

	for (i = 0, rc = 1; i < 10; i++, rc = mul_by_x(rc)) {
		uint32_t *rki = RK + (i * kwords);
		uint32_t *rko = rki + kwords;

		rko[0] = ror32(subw(rki[kwords - 1]), 8) ^ rc ^ rki[0];
		rko[1] = rko[0] ^ rki[1];
		rko[2] = rko[1] ^ rki[2];
		rko[3] = rko[2] ^ rki[3];

		if (key_len == 24) {
			if (i >= 7)
				break;
			rko[4] = rko[3] ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
		} else if (key_len == 32) {
			if (i >= 6)
				break;
			rko[4] = subw(rko[3]) ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
			rko[6] = rko[5] ^ rki[6];
			rko[7] = rko[6] ^ rki[7];
		}
	}
	return 0;
}
#endif

/*
 * AES key schedule (encryption)
 */
#if defined(MBEDTLS_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
#if AES_KEY_USE_VECTOR_K_ALT
    uint32_t *RK;

    switch( keybits )
    {
        case 128: ctx->nr = 10; ctx->key_length = 16; break;
        case 256: ctx->nr = 14; ctx->key_length = 32; break;
        default : return( MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED );
    }

    ctx->rk_offset = 0;
    RK = ctx->buf + ctx->rk_offset;

    rv64i_zvkned_set_encrypt_key(key, keybits, RK);
#else

    aes_expandkey(ctx, key, keybits >> 3);

#endif
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
#if AES_KEY_USE_VECTOR_K_ALT
    uint32_t *RK;

    switch( keybits )
    {
        case 128: ctx->nr = 10; ctx->key_length = 16; break;
        case 256: ctx->nr = 14; ctx->key_length = 32; break;
        default : return( MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED );
    }

    ctx->rk_offset = 0;
    RK = ctx->buf + ctx->rk_offset;

    rv64i_zvkned_set_decrypt_key(key, keybits, RK);
#else
    aes_expandkey(ctx, key, keybits >> 3);
#endif
    return 0;

}
#endif /* MBEDTLS_AES_SETKEY_DEC_ALT */

//#define printf
/*
 * AES-ECB block encryption
 */
#if defined(MBEDTLS_AES_ENCRYPT_ALT)
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    uint32_t *RK = ctx->buf + ctx->rk_offset;

    aes_encrypt_zvkned(RK, input, output);

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

    aes_decrypt_zvkned(RK, input, output);

    return( 0 );
}
#endif /* MBEDTLS_AES_DECRYPT_ALT */

#if defined(MBEDTLS_CIPHER_MODE_CBC) && defined(MBEDTLS_AES_CBC_ALT)
/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    uint32_t *RK = ctx->buf + ctx->rk_offset;

    if( mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT )
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;

    if( length % 16 != 0)
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_AES_DECRYPT ) {
      aes_cbc_decrypt_zvkned(RK, input, output, length, iv);
    } else {
      aes_cbc_encrypt_zvkned(RK, input, output, length, iv);
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* MBEDTLS_AES_C */
