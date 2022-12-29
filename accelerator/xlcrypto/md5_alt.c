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
#include "nuclei_sdk_soc.h"
#include "common.h"

#if defined(MBEDTLS_MD5_C)

// #define MBEDTLS_DEBUG

#include "hash_alt.h"
#include "mbedtls/md5.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#define MD5_BLOCK_SIZE          64

#if defined(MBEDTLS_MD5_DMA_ALT)
#define mbedtls_internal_md5_process_many            mbedtls_internal_md5_process_many_dma_alt
#define mbedtls_internal_md5_process_once            mbedtls_internal_md5_process_dma_alt
#else
#define mbedtls_internal_md5_process_many            mbedtls_internal_md5_process_many_alt
#define mbedtls_internal_md5_process_once            mbedtls_internal_md5_process_alt
#endif


static uint8_t isFstConfiged = 0;

/*
 * MD5 get result for HMAC
 */
#if defined(MBEDTLS_HMAC_FINISH_ALT)
int mbedtls_internal_md5_get_hmac_result(mbedtls_md5_context *ctx, unsigned char *out)
{
    uint32_t counter = 0;
    FlagStatus ret = 0;
    uint32_t * output = (uint32_t *)out;

    /* wait until the Busy flag is RESET */
    while((counter != MD_BUSY_TIMEOUT) && (ret == 0)) {
        counter++;
        ret = HASH_GetITStatus(HASH0, HASH_IT_HASHDONE);
    }
    HASH_ClearITPendingBit(HASH0, HASH_IT_HASHDONE);

    if(ret == 0) {
        return MD_TIMEOUT_ERR;
    } else {
        HASH_GetResult(HASH0, output, 4);
    }
    return( 0 );
}
#endif

static int mbedtls_internal_md5_process_dma_alt( mbedtls_md5_context *ctx,
                                    const uint8_t *data,
                                    uint32_t curlen,
                                    uint32_t hashHandleState )
{
    uint32_t counter = 0;
    FlagStatus ret = 0;
    uint32_t *output = (uint32_t *)ctx->state;
    uint32_t hashDownVal;
    uint8_t waitState = 1;

    if (hashHandleState == MD_HASH_DOWN) {
        hashDownVal = HASH_IT_HASHDONE;
    } else if (hashHandleState == MD_SEGMENT_DOWN){
        hashDownVal = HASH_IT_SEGDONE;
    } else if (hashHandleState == MD_OPAD) {
        hashDownVal = HASH_IT_OPAD;
    } else {
        waitState = 0;
    }

    /* HASH Interrupt Configuration */
    HASH_ITConfig(HASH0, HASH_IT_TIMEOUT, DISABLE);
    /* HASH DMA Configuration */
    HASH_DMA_CFG((uint32_t *)data, (curlen % 4) ? curlen / 4 * 4 + 4 : curlen);
    /* Enable HASH */
    HASH_Cmd(HASH0, ENABLE);
    /* Enable UDMA for HASH */
    UDMA_Cmd(HASH0_TX_DMA_DMA_CH, ENABLE);

    if (waitState == 1) {
        /* wait until the Busy flag is RESET */
        while((counter != MD_BUSY_TIMEOUT) && (ret == 0)) {
            counter++;
            ret = HASH_GetITStatus(HASH0, hashDownVal);
        }
        HASH_ClearITPendingBit(HASH0, hashDownVal);

        if(ret == 0) {
            return MD_TIMEOUT_ERR;
        } else {
            HASH_GetResult(HASH0, output, 4);
        }
    }
    return( 0 );
}

static int mbedtls_internal_md5_process_alt( mbedtls_md5_context *ctx,
                                const unsigned char data[MD5_BLOCK_SIZE],
                                uint32_t curlen,
                                uint32_t hashHandleState )
{
    uint32_t counter = 0;
    uint32_t len_last,len_for;
    FlagStatus ret = 0;
    uint32_t data_lst;
    uint8_t *input = (uint8_t *)data;
    uint32_t *output = (uint32_t *)ctx->state;
    uint32_t hashDownVal;
    uint8_t waitState = 1;

    if (hashHandleState == MD_HASH_DOWN) {
        hashDownVal = HASH_IT_HASHDONE;
    } else if (hashHandleState == MD_SEGMENT_DOWN){
        hashDownVal = HASH_IT_SEGDONE;
    } else if (hashHandleState == MD_OPAD) {
        hashDownVal = HASH_IT_OPAD;
    } else {
        waitState = 0;
    }

    /* HASH Interrupt Configuration */
    HASH_ITConfig(HASH0, HASH_IT_TIMEOUT, DISABLE);
    /* Enable HASH */
    HASH_Cmd(HASH0, ENABLE);

    len_last = curlen % 4;

    if (len_last == 0) {
        len_for = curlen / 4;
    } else {
        len_for = ((uint32_t)curlen / 4) + 1;
    }

    for (uint32_t i = 0; i < len_for; i++) {
        while (ret == 0) {
            ret = HASH_GetITStatus(HASH0, HASH_IT_FIFOWRQ);
        }
        HASH_DataIn(HASH0, *((uint32_t *)input));
        input += 4;
        ret = 0;
        HASH_ClearITPendingBit(HASH0, HASH_IT_FIFOWRQ);
    }

    if (waitState == 1) {
        /* wait until the Busy flag is RESET */
        while((counter != MD_BUSY_TIMEOUT) && (ret == 0)) {
            counter++;
            ret = HASH_GetITStatus(HASH0, hashDownVal);
        }
        HASH_ClearITPendingBit(HASH0, hashDownVal);

        if(ret == 0) {
            return MD_TIMEOUT_ERR;
        } else {
            HASH_GetResult(HASH0, output, 4);
        }
    }
    return( 0 );
}

static size_t mbedtls_internal_md5_process_many_alt(
                  mbedtls_md5_context *ctx, const uint8_t *data, size_t len )
{
    size_t processed = 0;

    while( len >= MD5_BLOCK_SIZE ) {
        if( mbedtls_internal_md5_process_once( ctx, data, MD5_BLOCK_SIZE, MD_SEGMENT_DOWN ) != 0)
            return( 0 );

        data += MD5_BLOCK_SIZE;
        len  -= MD5_BLOCK_SIZE;
        processed += MD5_BLOCK_SIZE;
        /* set Not First Segment */
        HASH0->CTRL &= ~HASH_CR_FST_SEG;
    }
    return( processed );
}

static size_t mbedtls_internal_md5_process_many_dma_alt(
                  mbedtls_md5_context *ctx, const uint8_t *data, size_t len)
{
    size_t processed = 0;
    uint32_t blockNum = (uint32_t)((len / MD5_BLOCK_SIZE) * MD5_BLOCK_SIZE);

    while( len >= MD5_BLOCK_SIZE ) {
        if( mbedtls_internal_md5_process_once( ctx, data, blockNum, MD_SEGMENT_DOWN ) != 0)
            return( 0 );

        data += blockNum;
        processed += blockNum;
        len -= blockNum;
        /* set Not First Segment */
        HASH0->CTRL &= ~HASH_CR_FST_SEG;
    }
    return( processed );
}

/*
 * MD5 process key
 */
#if defined(MBEDTLS_MD_UPDATE_ALT)
int mbedtls_md5_update_key( mbedtls_md5_context *ctx,
                               const unsigned char *key,
                               size_t keylen,
                               uint8_t keystate)
{
    HASH_InitTypeDef HASH_InitStructure;
    HASH_SegLenInitTypeDef HASH_SegLenInitStruct;

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t hashDownState;
    uint32_t hashAlgo;

    if( keylen == 0 )
        return( 0 );

    hashAlgo = ctx->total[1] & 0x1;
    hashDownState = (ctx->total[1] >> 1) & 0x7;

    if (( hashAlgo != MD_HMAC_ALGO ) || (( hashDownState != MD_HMAC_FST_KEY ) && ( hashDownState != MD_HMAC_LST_KEY ))) {
        return ret;
    }
    if (( keystate != HMAC_SET_FST_KEY ) && ( keystate != HMAC_SET_LST_KEY )) {
        return ret;
    }

    if (keystate == HMAC_SET_FST_KEY) {
        if (!isFstConfiged) {
            isFstConfiged = 1;
            /* HASH Configuration */
            HASH_InitStructure.HASH_AlgoSelection = HASH_AlgoSelection_MD5;
            HASH_InitStructure.HASH_AlgoMode = HASH_AlgoMode_HMAC;
            HASH_InitStructure.HASH_DataType = HASH_DataType_8b;
            HASH_InitStructure.HASH_DmaEn = 0;
            HASH_InitStructure.HASH_TimeOut = MD_BUSY_TIMEOUT;

            /* HASH Frist segment Configuration */
            //hmac update key need configure first segment
            HASH_InitStructure.HASH_First_Seg = HASH_CR_FST_SEG;
            HASH_InitStructure.HASH_Last_Seg = 0;
            /* HASH CurrLen Configuration */
            HASH_SegLenInitStruct.HASH_Seg_CurrLen = MD5_BLOCK_SIZE;
            HASH_Ip_Init(HASH0);
            HASH_Init(HASH0,&HASH_InitStructure);
            HASH_SegCurLenInit(HASH0, &HASH_SegLenInitStruct);
        }
    }

    if( ( ret = mbedtls_internal_md5_process_alt( ctx, key, MD5_BLOCK_SIZE, hashDownState ) ) != 0 )
        return( ret );

    return( 0 );
}
#endif

/*
 * MD5 process buffer
 */
#if defined(MBEDTLS_MD5_UPDATE_ALT)
int mbedtls_md5_update( mbedtls_md5_context *ctx,
                               const unsigned char *input,
                               size_t ilen )
{
    HASH_InitTypeDef HASH_InitStructure;
    HASH_SegLenInitTypeDef HASH_SegLenInitStruct;

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t fill;
    unsigned int left;
    uint32_t blockNum;
    uint32_t hashDownState;
    uint32_t hashAlgo;
    size_t processed = 0;

    if( ilen == 0 )
        return( 0 );

    hashAlgo = ctx->total[1] & 0x1;
    hashDownState = (ctx->total[1] >> 1) & 0x7;

    if( hashDownState != MD_SEGMENT_DOWN ) {
        return ret;
    }

    /* HASH Configuration */
    HASH_InitStructure.HASH_AlgoSelection = HASH_AlgoSelection_MD5;
    if( hashAlgo == MD_HASH_ALGO ) {
        HASH_InitStructure.HASH_AlgoMode = HASH_AlgoMode_HASH;
    } else {
        HASH_InitStructure.HASH_AlgoMode = HASH_AlgoMode_HMAC;
    }

    HASH_InitStructure.HASH_DataType = HASH_DataType_8b;
#if defined(MBEDTLS_MD5_DMA_ALT)
    HASH_InitStructure.HASH_DmaEn = HASH_CR_DMAEN;
#else
    HASH_InitStructure.HASH_DmaEn = 0;
#endif
    HASH_InitStructure.HASH_TimeOut = MD_BUSY_TIMEOUT;

    left = (unsigned int) (ctx->total[0] & 0x3F);
    fill = MD5_BLOCK_SIZE - left;

    ctx->total[0] += (uint64_t) ilen;

    if( left && ilen >= fill )
    {
        if (!isFstConfiged) {
            isFstConfiged = 1;
            /* HASH Frist segment Configuration */
            HASH_InitStructure.HASH_First_Seg = HASH_CR_FST_SEG;
            HASH_InitStructure.HASH_Last_Seg = 0;
            /* HASH CurrLen Configuration */
            HASH_SegLenInitStruct.HASH_Seg_CurrLen = MD5_BLOCK_SIZE;
            HASH_Ip_Init(HASH0);
            HASH_Init(HASH0, &HASH_InitStructure);
            HASH_SegCurLenInit(HASH0, &HASH_SegLenInitStruct);
        } else {
            /* HASH Middle segment Configuration */
            HASH_InitStructure.HASH_First_Seg = 0;
            HASH_InitStructure.HASH_Last_Seg = 0;
            /* HASH CurrLen Configuration */
            HASH_SegLenInitStruct.HASH_Seg_CurrLen = MD5_BLOCK_SIZE;
            HASH_Ip_Init(HASH0);
            HASH_Init(HASH0, &HASH_InitStructure);
            HASH_SegCurLenInit(HASH0, &HASH_SegLenInitStruct);
        }

        memcpy( (void *) (ctx->buffer + left), input, fill );

        if( ( ret = mbedtls_internal_md5_process_once( ctx, ctx->buffer, MD5_BLOCK_SIZE, MD_SEGMENT_DOWN ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    blockNum = (uint32_t)((ilen / MD5_BLOCK_SIZE) * MD5_BLOCK_SIZE);

    while( ilen >= MD5_BLOCK_SIZE )
    {
        if (!isFstConfiged) {
            isFstConfiged = 1;
            /* HASH Frist segment Configuration */
            HASH_InitStructure.HASH_First_Seg = HASH_CR_FST_SEG;
            HASH_InitStructure.HASH_Last_Seg = 0;
            /* HASH CurrLen Configuration */
        #if defined(MBEDTLS_MD5_DMA_ALT)
            HASH_SegLenInitStruct.HASH_Seg_CurrLen = blockNum;
        #else
            HASH_SegLenInitStruct.HASH_Seg_CurrLen = MD5_BLOCK_SIZE;
        #endif
            HASH_Ip_Init(HASH0);
            HASH_Init(HASH0, &HASH_InitStructure);
            HASH_SegCurLenInit(HASH0, &HASH_SegLenInitStruct);
        } else {
            /* HASH Middle segment Configuration */
            HASH_InitStructure.HASH_First_Seg = 0;
            HASH_InitStructure.HASH_Last_Seg = 0;
            /* HASH CurrLen Configuration */
        #if defined(MBEDTLS_MD5_DMA_ALT)
            HASH_SegLenInitStruct.HASH_Seg_CurrLen = blockNum;
        #else
            HASH_SegLenInitStruct.HASH_Seg_CurrLen = MD5_BLOCK_SIZE;
        #endif
            HASH_Ip_Init(HASH0);
            HASH_Init(HASH0, &HASH_InitStructure);
            HASH_SegCurLenInit(HASH0, &HASH_SegLenInitStruct);
        }

        processed = mbedtls_internal_md5_process_many( ctx, input, ilen );

        if( processed < MD5_BLOCK_SIZE )
            return( MBEDTLS_ERR_ERROR_GENERIC_ERROR );

        input += processed;
        ilen  -= processed;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );

    return( 0 );
}
#endif

/*
 * MD5 final digest
 */
#if defined(MBEDTLS_MD5_FINISH_ALT)
int mbedtls_md5_finish( mbedtls_md5_context *ctx,
                               unsigned char *output )
{
    HASH_InitTypeDef HASH_InitStructure;
    HASH_SegLenInitTypeDef HASH_SegLenInitStruct;

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned used;
    uint64_t high, low;
    uint32_t hashDownState;
    uint32_t hashAlgo;

    hashAlgo = ctx->total[1] & 0x1;
    hashDownState = (ctx->total[1] >> 1) & 0x7;

    if ( hashAlgo == MD_HMAC_ALGO ) {
        if(( hashDownState != MD_HASH_DOWN ) && ( hashDownState != MD_OPAD )) {
            return ret;
        }
    }

    /* HASH Configuration */
    HASH_InitStructure.HASH_AlgoSelection = HASH_AlgoSelection_MD5;
    if( hashAlgo == MD_HASH_ALGO ) {
        HASH_InitStructure.HASH_AlgoMode = HASH_AlgoMode_HASH;
    } else {
        HASH_InitStructure.HASH_AlgoMode = HASH_AlgoMode_HMAC;
    }
    HASH_InitStructure.HASH_DataType = HASH_DataType_8b;
#if defined(MBEDTLS_MD5_DMA_ALT)
    HASH_InitStructure.HASH_DmaEn = HASH_CR_DMAEN;
#else
    HASH_InitStructure.HASH_DmaEn = 0;
#endif
    HASH_InitStructure.HASH_TimeOut = MD_BUSY_TIMEOUT;

    used = ctx->total[0] & 0x3F;

    /* HASH Totallen Configuration */
    HASH_SegLenInitStruct.HASH_Seg_TotalLen[0] = ctx->total[0];
    HASH_SegLenInitStruct.HASH_Seg_TotalLen[1] = 0;
    HASH_SegLenInitStruct.HASH_Seg_TotalLen[2] = 0;
    HASH_SegLenInitStruct.HASH_Seg_TotalLen[3] = 0;
    /* HASH Curlen Configuration */
    HASH_SegLenInitStruct.HASH_Seg_CurrLen = used;

    if (!isFstConfiged) {
        /* HASH Last segment Configuration */
        HASH_InitStructure.HASH_First_Seg = HASH_CR_FST_SEG;
        HASH_InitStructure.HASH_Last_Seg = HASH_CR_LST_SEG;
        HASH_Ip_Init(HASH0);
        HASH_Init(HASH0, &HASH_InitStructure);
        HASH_SegLenInit(HASH0, &HASH_InitStructure, &HASH_SegLenInitStruct);
    } else {
        /* HASH Last segment Configuration */
        HASH_InitStructure.HASH_First_Seg = 0;
        HASH_InitStructure.HASH_Last_Seg = HASH_CR_LST_SEG;
        HASH_Ip_Init(HASH0);
        HASH_Init(HASH0, &HASH_InitStructure);
        HASH_SegLenInit(HASH0, &HASH_InitStructure, &HASH_SegLenInitStruct);
    }

    /* reset isFstConfiged */
    isFstConfiged = 0;

    if( hashAlgo == MD_HASH_ALGO ) {
        hashDownState = MD_HASH_DOWN;
    }

    if( ( ret = mbedtls_internal_md5_process_once( ctx, ctx->buffer, used, hashDownState ) ) != 0 )
        return( ret );

    /*
     * Output final state
     */
    MBEDTLS_PUT_UINT32_LE( ctx->state[0], output,  0 );
    MBEDTLS_PUT_UINT32_LE( ctx->state[1], output,  4 );
    MBEDTLS_PUT_UINT32_LE( ctx->state[2], output,  8 );
    MBEDTLS_PUT_UINT32_LE( ctx->state[3], output, 12 );

    return( 0 );
}
#endif

#endif /* MBEDTLS_MD5_C */