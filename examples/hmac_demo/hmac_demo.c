/**
 * MD API multi-part HMAC demonstration.
 *
 * This programs computes the HMAC of two messages using the multi-part API.
 *
 * This is a companion to psa/hmac_demo.c, doing the same operations with the
 * legacy MD API. The goal is that comparing the two programs will help people
 * migrating to the PSA Crypto API.
 *
 * When it comes to multi-part HMAC operations, the `mbedtls_md_context`
 * serves a dual purpose (1) hold the key, and (2) save progress information
 * for the current operation. With PSA those roles are held by two disinct
 * objects: (1) a psa_key_id_t to hold the key, and (2) a psa_operation_t for
 * multi-part progress.
 *
 * This program and its companion psa/hmac_demo.c illustrate this by doing the
 * same sequence of multi-part HMAC computation with both APIs; looking at the
 * two side by side should make the differences and similarities clear.
 */

/*
 *  Copyright (c) 2009-2018 Arm Limited. All rights reserved.
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

/* First include Mbed TLS headers to get the Mbed TLS configuration and
 * platform definitions that we'll use in this program. Also include
 * standard C headers for functions we'll use here. */

#include "mbedtls/build_info.h"

#include "mbedtls/md.h"

#include "mbedtls/platform_util.h" // for mbedtls_platform_zeroize

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* HMAC hardware acceleration algorithm, user can choose one to run HMAC.
 * MBEDTLS_MD_MD5
 * MBEDTLS_MD_SHA1
 * MBEDTLS_MD_SHA224
 * MBEDTLS_MD_SHA256
 * MBEDTLS_MD_SHA384
 * MBEDTLS_MD_SHA512
 */
#define HMAC_ALGO       MBEDTLS_MD_SHA256

#define HMAC_CMP_FAIL   (-1)

/* If the build options we need are not enabled, compile a placeholder. */
#if !defined(MBEDTLS_MD_C)
int main( void )
{
    printf( "MBEDTLS_MD_C not defined\r\n" );
    return( 0 );
}
#else

/* The real program starts here. */

/* Dummy inputs for HMAC */
const unsigned char msg1_part1[] = { 0x01, 0x02 };
const unsigned char msg1_part2[] = { 0x03, 0x04 };
const unsigned char msg2_part1[] = { 0x05, 0x05 };
const unsigned char msg2_part2[] = { 0x06, 0x06 };

/* HMAC MD5 result */
static const unsigned char md5_hmac_result[][16] =
{
    { 0x7f, 0x8a, 0xde, 0xa1, 0x9a, 0x1a, 0xc0, 0x21,
      0x86, 0xfa, 0x89, 0x5a, 0xf7, 0x2a, 0x7f, 0xa1 },
    { 0xa0, 0xe6, 0xdc, 0xa9, 0xef, 0x12, 0x08, 0x89,
      0x24, 0x16, 0x5e, 0xf1, 0x94, 0xa9, 0x48, 0x38 },
};

/* HMAC SHA1 result */
static const unsigned char sha1_hmac_result[][20] =
{
    { 0xbc, 0x7f, 0x43, 0x03, 0x84, 0xbc, 0x2a, 0x2a,
      0x18, 0xe9, 0xe5, 0x59, 0xc5, 0x05, 0x7a, 0xad,
	  0x93, 0x6f, 0xa0, 0x13 },
	{ 0x42, 0xd6, 0x2b, 0xd6, 0xc5, 0x07, 0x9c, 0x8e,
	  0xd1, 0x4a, 0x92, 0xf4, 0x53, 0x43, 0x5a, 0x13,
	  0xb9, 0x49, 0x9b, 0x53 },
};

/* HMAC SHA224 result */
static const unsigned char sha224_hmac_result[][28] =
{
    { 0xb0, 0x7a, 0x57, 0x41, 0xea, 0xfa, 0xaa, 0xf9,
      0xde, 0xc5, 0xca, 0x23, 0xc0, 0x92, 0x83, 0xeb,
	  0xfa, 0xfe, 0x33, 0x48, 0x5a, 0xcd, 0x98, 0xc6,
	  0x11, 0x0b, 0x75, 0x6c },
	{ 0x2d, 0x22, 0xcd, 0x22, 0xea, 0x4a, 0x37, 0x32,
	  0x36, 0x08, 0xf1, 0x58, 0xd5, 0xd2, 0x1e, 0xc2,
	  0x4e, 0x4b, 0x25, 0xbb, 0x17, 0xa2, 0x72, 0x94,
	  0x73, 0xaf, 0x2c, 0x23 },
};

/* HMAC SHA256 result */
static const unsigned char sha256_hmac_result[][32] =
{
    { 0x26, 0x8b, 0xa3, 0x4e, 0x03, 0xbb, 0xb2, 0x73,
      0xd5, 0x6c, 0x45, 0xa7, 0x3c, 0x86, 0x5a, 0x0b,
      0xbc, 0xea, 0x28, 0xf0, 0xa9, 0x83, 0xf8, 0x6e,
      0x9e, 0x91, 0x56, 0xa1, 0x27, 0x78, 0x77, 0xf2 },
	{ 0x94, 0xd1, 0x9b, 0x37, 0x53, 0x5a, 0xca, 0x6c,
	  0x53, 0x13, 0x96, 0xb9, 0xdf, 0xb5, 0x0e, 0xce,
	  0x18, 0x2b, 0xe5, 0xd3, 0x39, 0x7e, 0x62, 0x61,
	  0x43, 0xf4, 0x34, 0x32, 0x71, 0x85, 0x12, 0xf2 },
};

/* HMAC SHA384 result */
static const unsigned char sha384_hmac_result[][48] =
{
    { 0x5f, 0x53, 0x60, 0x91, 0x67, 0xdd, 0xa5, 0xea,
      0xe5, 0x0b, 0x02, 0x9e, 0xc1, 0xe7, 0x6f, 0xcb,
      0x97, 0xd3, 0xe6, 0x72, 0xd2, 0x1c, 0x51, 0xd8,
      0x45, 0x5a, 0x49, 0x38, 0x42, 0xd5, 0x23, 0x47,
      0x0b, 0x93, 0xd3, 0x13, 0xf9, 0x47, 0xcd, 0xa8,
      0xae, 0xa2, 0x38, 0xba, 0x69, 0x5b, 0xc3, 0x91 },
	{ 0x8b, 0xf7, 0x46, 0x77, 0xe0, 0x74, 0x39, 0xac,
	  0xb0, 0x6c, 0x5b, 0x6a, 0x5c, 0xbd, 0xd5, 0x6e,
	  0x6e, 0x83, 0xd9, 0x8d, 0x91, 0xb7, 0x72, 0xa8,
	  0x23, 0xba, 0x9c, 0x4c, 0xdb, 0xa3, 0x7d, 0x73,
	  0x29, 0x8a, 0xcd, 0xab, 0x89, 0x80, 0x01, 0xc9,
	  0x04, 0x37, 0x4e, 0xfa, 0x0e, 0x71, 0x4e, 0xe9 },
};

/* HMAC SHA512 result */
static const unsigned char sha512_hmac_result[][64] =
{
    { 0x7a, 0x5b, 0xcd, 0x03, 0xc6, 0xd2, 0x68, 0x5d,
      0x59, 0xaf, 0x54, 0xbb, 0xaa, 0x30, 0xa9, 0xf9,
      0xa5, 0x24, 0xdc, 0xc1, 0x13, 0x99, 0x69, 0xe6,
      0x27, 0xd7, 0x82, 0xe7, 0x4a, 0xdf, 0x02, 0x84,
      0x1b, 0xd6, 0x84, 0xec, 0x75, 0xd4, 0x4a, 0x16,
      0x46, 0xc5, 0xc0, 0x88, 0x6d, 0x3c, 0xa1, 0x93,
      0xa6, 0xb2, 0x6e, 0x3c, 0x7f, 0xd0, 0x2d, 0x6a,
      0x2b, 0x9d, 0xd3, 0x85, 0x1f, 0x93, 0xcc, 0x67 },
	{ 0xa1, 0x3d, 0x8a, 0x8f, 0x96, 0x56, 0xbe, 0x8a,
	  0xfe, 0xfb, 0x71, 0x98, 0x4e, 0x81, 0x9b, 0x5c,
	  0x41, 0x21, 0x79, 0xe3, 0x8c, 0x3f, 0x8b, 0x37,
	  0xb7, 0xea, 0x7e, 0x30, 0xc0, 0x51, 0x7b, 0x79,
	  0x7b, 0x11, 0x73, 0x94, 0x9f, 0x0a, 0x06, 0xd0,
	  0xc4, 0xbd, 0xbc, 0xa3, 0x22, 0x88, 0x63, 0x08,
	  0xcb, 0x02, 0x80, 0x16, 0xb3, 0xd0, 0x37, 0x53,
	  0x2b, 0xf3, 0xc4, 0x28, 0x12, 0xfa, 0xd7, 0x3d },
};

/* Dummy key material - never do this in production!
 * This example program uses SHA-256, so a 32-byte key makes sense. */
const unsigned char key_bytes[32] = { 0 };

/* Print the contents of a buffer in hex */
void print_buf( const char *title, unsigned char *buf, size_t len )
{
    printf( "%s:", title );
    for( size_t i = 0; i < len; i++ )
        printf( " %02x", buf[i] );
    printf( "\n" );
}

/* Run an Mbed TLS function and bail out if it fails.
 * A string description of the error code can be recovered with:
 * programs/util/strerror <value> */
#define CHK( expr )                                             \
    do                                                          \
    {                                                           \
        ret = ( expr );                                         \
        if( ret != 0 )                                          \
        {                                                       \
            printf( "Error %d at line %d: %s\n",                \
                    ret,                                        \
                    __LINE__,                                   \
                    #expr );                                    \
            goto exit;                                          \
        }                                                       \
    } while( 0 )

/*
 * This function verifies that the corresponding HMAC algorithm runs correctly.
 */
static int hmac_res_compare(unsigned char *output, int len, mbedtls_md_type_t algo, unsigned char num )
{
	switch (algo) {
		case MBEDTLS_MD_MD5:
		    if( memcmp( output, md5_hmac_result[num], len ) != 0 )
		    {
		    	return HMAC_CMP_FAIL;
		    }
		    break;
		case MBEDTLS_MD_SHA1:
		    if( memcmp( output, sha1_hmac_result[num], len ) != 0 )
		    {
		    	return HMAC_CMP_FAIL;
		    }
		    break;
		case MBEDTLS_MD_SHA224:
		    if( memcmp( output, sha224_hmac_result[num], len ) != 0 )
		    {
		    	return HMAC_CMP_FAIL;
		    }
		    break;
		case MBEDTLS_MD_SHA256:
		    if( memcmp( output, sha256_hmac_result[num], len ) != 0 )
		    {
		    	return HMAC_CMP_FAIL;
		    }
		    break;
		case MBEDTLS_MD_SHA384:
		    if( memcmp( output, sha384_hmac_result[num], len ) != 0 )
		    {
		    	return HMAC_CMP_FAIL;
		    }
		    break;
		case MBEDTLS_MD_SHA512:
		    if( memcmp( output, sha512_hmac_result[num], len ) != 0 )
		    {
		    	return HMAC_CMP_FAIL;
		    }
		    break;
        default:
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
	}
	printf("%d HMAC success\n",num);
	return 0;
}

/*
 * This function demonstrates computation of the HMAC of two messages using
 * the multipart API.
 */
int hmac_demo(void)
{
    int ret;
    const mbedtls_md_type_t alg = HMAC_ALGO;
    unsigned char out[MBEDTLS_MD_MAX_SIZE]; // safe but not optimal

    mbedtls_md_context_t ctx;

    mbedtls_md_init( &ctx );

    /* prepare context and load key */
    // the last argument to setup is 1 to enable HMAC (not just hashing)
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type( alg );
    CHK( mbedtls_md_setup( &ctx, info, 1 ) );
    CHK( mbedtls_md_hmac_starts( &ctx, key_bytes, sizeof( key_bytes ) ) );

    /* compute HMAC(key, msg1_part1 | msg1_part2) */
    CHK( mbedtls_md_hmac_update( &ctx, msg1_part1, sizeof( msg1_part1 ) ) );
    CHK( mbedtls_md_hmac_update( &ctx, msg1_part2, sizeof( msg1_part2 ) ) );
    CHK( mbedtls_md_hmac_finish( &ctx, out ) );
    CHK( hmac_res_compare( out, (int)mbedtls_md_get_size( info ), alg, 0) );
    // printf("mbedtls_md_get_size( info ): %d\n",mbedtls_md_get_size( info ));
    // for( size_t i = 0; i < mbedtls_md_get_size( info ); i++ ) {
    //     printf( "%02x\n", out[i] );
    // }

    /* compute HMAC(key, msg2_part1 | msg2_part2) */
    CHK( mbedtls_md_hmac_reset( &ctx ) ); // prepare for new operation
    CHK( mbedtls_md_hmac_update( &ctx, msg2_part1, sizeof( msg2_part1 ) ) );
    CHK( mbedtls_md_hmac_update( &ctx, msg2_part2, sizeof( msg2_part2 ) ) );
    CHK( mbedtls_md_hmac_finish( &ctx, out ) );
    CHK( hmac_res_compare( out, (int)mbedtls_md_get_size( info ), alg, 1 ) );
    // printf("mbedtls_md_get_size( info ): %d\n",mbedtls_md_get_size( info ));
    // for( size_t i = 0; i < mbedtls_md_get_size( info ); i++ ) {
    //     printf( "%02x\n", out[i] );
    // }

exit:
    mbedtls_md_free( &ctx );
    mbedtls_platform_zeroize( out, sizeof( out ) );

    return( ret );
}

int main(void)
{
    int ret;

    CHK( hmac_demo() );

exit:
    return( ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE );
}

#endif
