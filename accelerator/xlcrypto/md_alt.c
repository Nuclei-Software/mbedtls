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

#if defined(MBEDTLS_MD_C)

// #define MBEDTLS_DEBUG

#include "hash_alt.h"
#include "mbedtls/md.h"
#include "md_wrap.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <string.h>

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#endif


#if defined(MBEDTLS_HMAC_START_ALT)
int mbedtls_md_hmac_starts( mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char sum[MBEDTLS_MD_MAX_SIZE];
    unsigned char *ipad, *opad;
    size_t i;
    uint32_t *p;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    p = (uint32_t *)ctx->md_ctx;

    //calc key for hmac: hash algo
    if ( keylen > (size_t) ctx->md_info->block_size ) {
        if ( ( ret = mbedtls_md_starts( ctx ) ) != 0 )
            goto cleanup;

        if ((ctx->md_info->type == MBEDTLS_MD_SHA384) || (ctx->md_info->type == MBEDTLS_MD_SHA512)) {
        	p++;
        	p++;
        } else {
        	p++;
        }
        *p |= MD_HASH_ALGO | MD_SEGMENT_DOWN << 1;
        if( ( ret = mbedtls_md_update( ctx, key, keylen ) ) != 0 )
            goto cleanup;

        *p &= 0xfffffff0;
        *p |= MD_HASH_ALGO | MD_HASH_DOWN << 1;
        if( ( ret = mbedtls_md_finish( ctx, sum ) ) != 0 )
            goto cleanup;

        keylen = ctx->md_info->size;
        key = sum;
    }

    //padding keylen to blocksize
    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    for ( i = 0; i < keylen; i++ ) {
        ipad[i] = (unsigned char)( key[i] );
    }
    for ( ; i < ctx->md_info->block_size; i++ ) {
        ipad[i] = 0;
    }

    //transfer to opad key
    memcpy((unsigned char *)opad, (unsigned char *)ipad, ctx->md_info->block_size);

    if ( ( ret = mbedtls_md_starts( ctx ) ) != 0 )
        goto cleanup;

    //update hmac input frist key
    p = (uint32_t *)ctx->md_ctx;
    if ((ctx->md_info->type == MBEDTLS_MD_SHA384) || (ctx->md_info->type == MBEDTLS_MD_SHA512)) {
        p++;
        p++;
    } else {
        p++;
    }
    *p |= MD_HMAC_ALGO | MD_HMAC_FST_KEY << 1;
    if ( ( ret = mbedtls_md_update( ctx, ipad,
                                   ctx->md_info->block_size ) ) != 0 )
        goto cleanup;

cleanup:
    mbedtls_platform_zeroize( sum, sizeof( sum ) );

    return( ret );
}
#endif

#if defined(MBEDTLS_HMAC_UPDATE_ALT)
int mbedtls_md_hmac_update( mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    uint32_t *p;

    if ( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    //update hmac input data
    p = (uint32_t *)ctx->md_ctx;
    if ((ctx->md_info->type == MBEDTLS_MD_SHA384) || (ctx->md_info->type == MBEDTLS_MD_SHA512)) {
        p++;
        p++;
    } else {
        p++;
    }
    *p &= 0xfffffff0;
    *p |= MD_HMAC_ALGO | MD_SEGMENT_DOWN << 1;
    return( mbedtls_md_update( ctx, input, ilen ) );
}
#endif

#if defined(MBEDTLS_MD_UPDATE_ALT)
int mbedtls_md_update( mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    uint32_t *p;
    uint8_t hmac_key_state;

    if ( ctx == NULL || ctx->md_info == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    p = (uint32_t *)ctx->md_ctx;
    if ((ctx->md_info->type == MBEDTLS_MD_SHA384) || (ctx->md_info->type == MBEDTLS_MD_SHA512)) {
        p++;
        p++;
    } else {
        p++;
    }
    if ( ((*p >> 1) & 0x7) == MD_HMAC_FST_KEY ) {
        hmac_key_state = HMAC_SET_FST_KEY;
    } else if ( ((*p >> 1) & 0x7) == MD_HMAC_LST_KEY ) {
        hmac_key_state = HMAC_SET_LST_KEY;
    } else {
        hmac_key_state = HMAC_NONE_SET_KEY;
    }

    switch ( ctx->md_info->type ) {
#if defined(MBEDTLS_MD5_C)
        case MBEDTLS_MD_MD5:
            if ( hmac_key_state == HMAC_NONE_SET_KEY ) {
                return( mbedtls_md5_update( ctx->md_ctx, input, ilen ) );
            } else if ( hmac_key_state == HMAC_SET_FST_KEY) {
                return( mbedtls_md5_update_key( ctx->md_ctx, input, ilen, HMAC_SET_FST_KEY ) );
            } else {
                return( mbedtls_md5_update_key( ctx->md_ctx, input, ilen, HMAC_SET_LST_KEY ) );
            }
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case MBEDTLS_MD_RIPEMD160:
            return( mbedtls_ripemd160_update( ctx->md_ctx, input, ilen ) );
#endif
#if defined(MBEDTLS_SHA1_C)
        case MBEDTLS_MD_SHA1:
            if ( hmac_key_state == HMAC_NONE_SET_KEY ) {
                return( mbedtls_sha1_update( ctx->md_ctx, input, ilen ) );
            } else if ( hmac_key_state == HMAC_SET_FST_KEY) {
                return( mbedtls_sha1_update_key( ctx->md_ctx, input, ilen, HMAC_SET_FST_KEY ) );
            } else {
                return( mbedtls_sha1_update_key( ctx->md_ctx, input, ilen, HMAC_SET_LST_KEY ) );
            }
#endif
#if defined(MBEDTLS_SHA224_C)
        case MBEDTLS_MD_SHA224:
            if ( hmac_key_state == HMAC_NONE_SET_KEY ) {
                return( mbedtls_sha256_update( ctx->md_ctx, input, ilen ) );
            } else if ( hmac_key_state == HMAC_SET_FST_KEY) {
                return( mbedtls_sha256_update_key( ctx->md_ctx, input, ilen, HMAC_SET_FST_KEY ) );
            } else {
                return( mbedtls_sha256_update_key( ctx->md_ctx, input, ilen, HMAC_SET_LST_KEY ) );
            }
#endif
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_MD_SHA256:
            if ( hmac_key_state == HMAC_NONE_SET_KEY ) {
                return( mbedtls_sha256_update( ctx->md_ctx, input, ilen ) );
            } else if ( hmac_key_state == HMAC_SET_FST_KEY) {
                return( mbedtls_sha256_update_key( ctx->md_ctx, input, ilen, HMAC_SET_FST_KEY ) );
            } else {
                return( mbedtls_sha256_update_key( ctx->md_ctx, input, ilen, HMAC_SET_LST_KEY ) );
            }
#endif
#if defined(MBEDTLS_SHA384_C)
        case MBEDTLS_MD_SHA384:
            if ( hmac_key_state == HMAC_NONE_SET_KEY ) {
                return( mbedtls_sha512_update( ctx->md_ctx, input, ilen ) );
            } else if ( hmac_key_state == HMAC_SET_FST_KEY) {
                return( mbedtls_sha512_update_key( ctx->md_ctx, input, ilen, HMAC_SET_FST_KEY ) );
            } else {
                return( mbedtls_sha512_update_key( ctx->md_ctx, input, ilen, HMAC_SET_LST_KEY ) );
            }
#endif
#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA512:
            if ( hmac_key_state == HMAC_NONE_SET_KEY ) {
                return( mbedtls_sha512_update( ctx->md_ctx, input, ilen ) );
            } else if ( hmac_key_state == HMAC_SET_FST_KEY) {
                return( mbedtls_sha512_update_key( ctx->md_ctx, input, ilen, HMAC_SET_FST_KEY ) );
            } else {
                return( mbedtls_sha512_update_key( ctx->md_ctx, input, ilen, HMAC_SET_LST_KEY ) );
            }
#endif
        default:
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }
}
#endif

#if defined(MBEDTLS_HMAC_RESET_ALT)
int mbedtls_md_hmac_reset( mbedtls_md_context_t *ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *ipad;
    uint32_t *p;

    if ( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    p = (uint32_t *)ctx->md_ctx;
    ipad = (unsigned char *) ctx->hmac_ctx;

    if ( ( ret = mbedtls_md_starts( ctx ) ) != 0 )
        return( ret );

    //update hmac input first key
    p = (uint32_t *)ctx->md_ctx;
    if ((ctx->md_info->type == MBEDTLS_MD_SHA384) || (ctx->md_info->type == MBEDTLS_MD_SHA512)) {
        p++;
        p++;
    } else {
        p++;
    }
    *p |= MD_HMAC_ALGO | MD_HMAC_FST_KEY << 1;

    return( mbedtls_md_update( ctx, ipad, ctx->md_info->block_size ) );
}
#endif

#if defined(MBEDTLS_HMAC_FINISH_ALT)
static int mbedtls_md_get_result( mbedtls_md_context_t *ctx, unsigned char *output )
{
    if ( ctx == NULL || ctx->md_info == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    switch ( ctx->md_info->type ) {
#if defined(MBEDTLS_MD5_C)
        case MBEDTLS_MD_MD5:
            return( mbedtls_internal_md5_get_hmac_result( ctx->md_ctx, output ) );
#endif
#if defined(MBEDTLS_SHA1_C)
        case MBEDTLS_MD_SHA1:
            return( mbedtls_internal_sha1_get_hmac_result( ctx->md_ctx, output ) );
#endif
#if defined(MBEDTLS_SHA224_C)
        case MBEDTLS_MD_SHA224:
            return( mbedtls_internal_sha256_get_hmac_result( ctx->md_ctx, output ) );
#endif
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_MD_SHA256:
            return( mbedtls_internal_sha256_get_hmac_result( ctx->md_ctx, output ) );
#endif
#if defined(MBEDTLS_SHA384_C)
        case MBEDTLS_MD_SHA384:
            return( mbedtls_internal_sha512_get_hmac_result( ctx->md_ctx, output ) );
#endif
#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA512:
            return( mbedtls_internal_sha512_get_hmac_result( ctx->md_ctx, output ) );
#endif
        default:
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }
}

int mbedtls_md_hmac_finish( mbedtls_md_context_t *ctx, unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tmp[MBEDTLS_MD_MAX_SIZE];
    unsigned char *opad;
    uint32_t *p;

    if ( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    //get hmac opad result
    p = (uint32_t *)ctx->md_ctx;
    if ((ctx->md_info->type == MBEDTLS_MD_SHA384) || (ctx->md_info->type == MBEDTLS_MD_SHA512)) {
        p++;
        p++;
    } else {
        p++;
    }
    *p &= 0xfffffff0;
    *p |= MD_HMAC_ALGO | MD_OPAD << 1;

    if ( ( ret = mbedtls_md_finish( ctx, tmp ) ) != 0 )
        return( ret );

    if ( ( ret = mbedtls_md_starts( ctx ) ) != 0 )
        return( ret );

    //update hmac input last key
    p = (uint32_t *)ctx->md_ctx;
    if ((ctx->md_info->type == MBEDTLS_MD_SHA384) || (ctx->md_info->type == MBEDTLS_MD_SHA512)) {
        p++;
        p++;
    } else {
        p++;
    }
    *p &= 0xfffffff0;
    *p |= MD_HMAC_ALGO | MD_HMAC_LST_KEY << 1;

    if ( ( ret = mbedtls_md_update( ctx, opad,
                                   ctx->md_info->block_size ) ) != 0 )
        return( ret );

    //get hmac total result
    mbedtls_md_get_result(ctx, output);

    return 0;
}
#endif

#endif /* MBEDTLS_MD_C */