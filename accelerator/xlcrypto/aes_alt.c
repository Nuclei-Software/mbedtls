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

#if defined(MBEDTLS_AES_C)

#include <string.h>

// #define MBEDTLS_DEBUG

#include "cryp_alt.h"
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


#define GET_UINT32_LE_PADDING_ONE_ZERO( data )                  \
    (                                                           \
          ( (uint32_t) ( data )[ 0 ]       )                    \
        | ( (uint32_t) ( data )[ 1 ] <<  8 )                    \
        | ( (uint32_t) ( data )[ 2 ] << 16 )                    \
        | ( (uint32_t) (0) << 24 )                              \
    )

#define GET_UINT32_LE_PADDING_TWO_ZERO( data )                  \
    (                                                           \
          ( (uint32_t) ( data )[ 0 ]       )                    \
        | ( (uint32_t) ( data )[ 1 ] <<  8 )                    \
        | ( (uint32_t) (0) << 16 )                              \
        | ( (uint32_t) (0) << 24 )                              \
    )

#define GET_UINT32_LE_PADDING_THREE_ZERO( data )                \
    (                                                           \
          ( (uint32_t) ( data )[ 0 ]       )                    \
        | ( (uint32_t) (0) << 8 )                               \
        | ( (uint32_t) (0) << 16 )                              \
        | ( (uint32_t) (0) << 24 )                              \
    )


/*
 * AES-ECB multi block encryption/decryption
 */
#if defined(MBEDTLS_AES_ECB_CRYPT_MULTI_ALT)
int mbedtls_aes_crypt_ecb_multi( mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char *input,
                            size_t length,
                            unsigned char *output )
{
    uint32_t i = 0;
    FlagStatus status = 0;
    uint32_t len;
    uint32_t *pIn;
    uint32_t *pOut;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};

    if ( length % 16 )
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

    pIn = (uint32_t *)input;
    pOut = (uint32_t *)output;
    len = length;
#if defined(MBEDTLS_AES_DMA_ALT)
    CRYP_Dma_Cfg(pIn, len, 0);
#endif

    /* CRYP Initialization Structure */
    AES_CRYP_InitStructure.CRYP_Algo  = CRYP_Algo_AES;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_ECB;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_OdatType_8b;
    AES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    AES_CRYP_InitStructure.CRYP_Dout_Cnt = len / 4;
    AES_CRYP_InitStructure.CRYP_Din_Cnt = len / 4;
    AES_CRYP_InitStructure.CRYP_Rlen = len % 16;

    AES_CRYP_InitStructure.CRYP_To_Th = len / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = len / 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = len / 4;

    if ( mode == MBEDTLS_AES_ENCRYPT ) {
        AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Encrypt;
    } else {
        AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Decrypt;
    }

    switch ( ctx->nr ) {
        case 10: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b; break;
        case 12: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b; break;
        case 14: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

#if defined(MBEDTLS_AES_DMA_ALT)
    /* Crypto Init for CRYP_AlgoDir_Decrypt process */
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);
    CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->CRYP_DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE)) {
            *pOut = CRYP_DataOut(CRYP0);
            pOut += 1;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
    } while (status == RESET);

    CRYP_Cmd(CRYP0, DISABLE);
#else
    while (len >= 16) {
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;

        /* Crypto Init for CRYP_AlgoDir_Decrypt process */
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
        if (len >= 16) {
            /* Write the Input block in the IN FIFO */
            for (i = 0;i < 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            /* Read the Output block from the Output FIFO */
            for (i = 0;i < 4;i++) {
                do {
                    status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
                } while (status == RESET);
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            len = len - 16;
        } else if (len != 0) {
            /* Write the last block in the IN FIFO */
            for (i = 0;i < len / 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            for (i = 0;i < 4 - len / 4;i++) {
                CRYP_DataIn(CRYP0, 0);
            }
            /* Read the Output block from the Output FIFO */
            do {
                status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
            } while (status == RESET);

            for (i = 0;i < 4;i++) {
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            break;
        }
        CRYP_Cmd(CRYP0, DISABLE);
    }
#endif
    return( 0 );
}
#endif

/*
 * AES-ECB one block encryption
 */
#if defined(MBEDTLS_AES_ENCRYPT_ALT)
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )

{
    uint32_t i = 0;
    FlagStatus status = 0;
    uint32_t len = 16;
    uint32_t *pIn;
    uint32_t *pOut;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};

    pIn = (uint32_t *)input;
    pOut = (uint32_t *)output;

#if defined(MBEDTLS_AES_DMA_ALT)
    CRYP_Dma_Cfg((uint32_t *)input, 16, 0);
#endif

    /* CRYP Initialization Structure */
    AES_CRYP_InitStructure.CRYP_Algo  = CRYP_Algo_AES;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_ECB;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_OdatType_8b;
    AES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
    AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;
    AES_CRYP_InitStructure.CRYP_Rlen = len % 16;

    AES_CRYP_InitStructure.CRYP_To_Th = len / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = 4;

    AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Encrypt;

    switch ( ctx->nr ) {
        case 10: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b; break;
        case 12: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b; break;
        case 14: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

#if defined(MBEDTLS_AES_DMA_ALT)
    /* Crypto Init for CRYP_AlgoDir_Decrypt process */
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);
    /* Enable Crypto DMA */
    CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->CRYP_DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE)) {
            *pOut = CRYP_DataOut(CRYP0);
            pOut += 1;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
    } while (status == RESET);

    CRYP_Cmd(CRYP0, DISABLE);
#else
    while (len >= 16) {
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;

        /* Crypto Init for CRYP_AlgoDir_Decrypt process */
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
        if (len >= 16) {
            /* Write the Input block in the IN FIFO */
            for (i = 0;i < 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            /* Read the Output block from the Output FIFO */
            for (i = 0;i < 4;i++) {
                do {
                    status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
                } while (status == RESET);
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            len = len - 16;
        } else if (len != 0) {
            /* Write the last block in the IN FIFO */
            for (i = 0;i < len / 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            for (i = 0;i < 4 - len / 4;i++) {
                CRYP_DataIn(CRYP0, 0);
            }
            /* Read the Output block from the Output FIFO */
            do {
                status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
            } while (status == RESET);

            for (i = 0;i < 4;i++) {
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            break;
        }
        CRYP_Cmd(CRYP0, DISABLE);
    }
#endif
    return( 0 );
}
#endif

/*
 * AES-ECB one block decryption
 */
#if defined(MBEDTLS_AES_DECRYPT_ALT)
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    uint32_t i = 0;
    FlagStatus status = 0;
    uint32_t len = 16;
    uint32_t *pIn;
    uint32_t *pOut;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};

    pIn = (uint32_t *)input;
    pOut = (uint32_t *)output;

#if defined(MBEDTLS_AES_DMA_ALT)
    CRYP_Dma_Cfg((uint32_t *)input, 16, 0);
#endif

    /* CRYP Initialization Structure */
    AES_CRYP_InitStructure.CRYP_Algo  = CRYP_Algo_AES;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_ECB;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_OdatType_8b;
    AES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
    AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;
    AES_CRYP_InitStructure.CRYP_Rlen = len % 16;

    AES_CRYP_InitStructure.CRYP_To_Th = len / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = 4;

    AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Decrypt;

    switch ( ctx->nr ) {
        case 10: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b; break;
        case 12: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b; break;
        case 14: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

#if defined(MBEDTLS_AES_DMA_ALT)
    /* Crypto Init for CRYP_AlgoDir_Decrypt process */
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);
    /* Enable Crypto DMA */
    CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->CRYP_DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE)) {
            *pOut = CRYP_DataOut(CRYP0);
            pOut += 1;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
    } while (status == RESET);

    CRYP_Cmd(CRYP0, DISABLE);
#else
    while (len >= 16) {
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;

        /* Crypto Init for CRYP_AlgoDir_Decrypt process */
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
        if (len >= 16) {
            /* Write the Input block in the IN FIFO */
            for (i = 0;i < 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            /* Read the Output block from the Output FIFO */
            for (i = 0;i < 4;i++) {
                do {
                    status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
                } while (status == RESET);
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            len = len - 16;
        } else if (len != 0) {
            /* Write the last block in the IN FIFO */
            for (i = 0;i < len / 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            for (i = 0;i < 4 - len / 4;i++) {
                CRYP_DataIn(CRYP0, 0);
            }
            /* Read the Output block from the Output FIFO */
            do {
                status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
            } while (status == RESET);

            for (i = 0;i < 4;i++) {
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            break;
        }
        CRYP_Cmd(CRYP0, DISABLE);
    }
#endif
    return( 0 );
}
#endif

/*
 * AES key set (encryption)
 */
#if defined(MBEDTLS_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    unsigned int i;
    uint32_t *RK;
    CRYP_KeyInitTypeDef AES_CRYP_KeyInitStructure;

    /* Crypto structures initialisation */
    CRYP_KeyStructInit(CRYP0, &AES_CRYP_KeyInitStructure);
    CRYP_Cmd(CRYP0, DISABLE);

    RK = ctx->buf;
    for ( i = 0; i < ( keybits >> 5 ); i++ ) {
        RK[i] = __REV(MBEDTLS_GET_UINT32_LE( key, i << 2 ));
    }

    switch ( keybits ) {
        case 128:
            ctx->nr = 10;
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &RK[0], 4 * 4);
            break;
        case 192:
            ctx->nr = 12;
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &RK[0], 6 * 4);
            break;
        case 256:
            ctx->nr = 14;
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &RK[0], 8 * 4);
            break;
        default :
            return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    /* Initializes the CRYP encrypto keys */
    CRYP_Key_Selection(CRYP0, CRYP_CFG_KEY);
    CRYP_FIFOFlush(CRYP0);
    CRYP_KeyInit(CRYP0, &AES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * AES key set (decryption)
 */
#if defined(MBEDTLS_AES_SETKEY_DEC_ALT)
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    uint32_t i;
    uint8_t pre_status = 0;
    uint32_t *RK;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};
    CRYP_KeyInitTypeDef AES_CRYP_KeyInitStructure;

    /* Crypto structures initialisation */
    CRYP_KeyStructInit(CRYP0, &AES_CRYP_KeyInitStructure);
    CRYP_Cmd(CRYP0, DISABLE);

    RK = ctx->buf;
    for ( i = 0; i < ( keybits >> 5 ); i++ ) {
        RK[i] = __REV(MBEDTLS_GET_UINT32_LE( key, i << 2 ));
    }

    switch ( keybits ) {
        case 128:
            ctx->nr = 10;
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &RK[0], 4 * 4);
            break;
        case 192:
            ctx->nr = 12;
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &RK[0], 6 * 4);
            break;
        case 256:
            ctx->nr = 14;
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &RK[0], 8 * 4);
            break;
        default :
            return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    /* Initializes the CRYP encrypto keys */
    CRYP_Key_Selection(CRYP0, CRYP_CFG_KEY);
    CRYP_FIFOFlush(CRYP0);
    CRYP_KeyInit(CRYP0, &AES_CRYP_KeyInitStructure);

    /* Crypto structures configure */
    AES_CRYP_InitStructure.CRYP_Algo = CRYP_Algo_AES;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_KEY;
    AES_CRYP_InitStructure.CRYP_AlgoDir = UNUSED;
    AES_CRYP_InitStructure.CRYP_DataType = UNUSED;
    AES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;
    AES_CRYP_InitStructure.CRYP_OdatType  = UNUSED;

    AES_CRYP_InitStructure.CRYP_Din_Cnt = UNUSED;
    AES_CRYP_InitStructure.CRYP_Dout_Cnt = UNUSED;
    AES_CRYP_InitStructure.CRYP_Rlen  = UNUSED;
    AES_CRYP_InitStructure.CRYP_To_Th = UNUSED;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = UNUSED;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = UNUSED;

    switch ( ctx->nr ) {
        case 10: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b; break;
        case 12: AES_CRYP_InitStructure.CRYP_KeySize  = CRYP_KeySize_192b; break;
        case 14: AES_CRYP_InitStructure.CRYP_KeySize  = CRYP_KeySize_256b; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);

    /* Select Configure KEY Mode */
    CRYP_Key_Selection(CRYP0, CRYP_CFG_KEY);

    /* Disable mdrst and Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);

    /* Wait until the key prepare has finished */
    do {
        pre_status = CRYP_GetITStatus(CRYP0, CRYP_IT_KPRD);
    } while (pre_status == RESET);
    CRYP_ClearITPendingBit(CRYP0, CRYP_IT_KPRD);

    CRYP_Cmd(CRYP0, DISABLE);

    /* Read the Output key from the register */
    for (i = 0;i < keybits / 32;i++) {
        *RK = CRYP_GetKey(CRYP0, i);
        RK += 1;
    }

    switch ( ctx->nr ) {
        case 10:
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &ctx->buf[0], 4 * 4);
            break;
        case 12:
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &ctx->buf[0], 6 * 4);
            break;
        case 14:
            memcpy(AES_CRYP_KeyInitStructure.CRYP_Key, &ctx->buf[0], 8 * 4);
            break;
    }

    /* Initializes the CRYP decrypto keys */
    CRYP_Key_Selection(CRYP0, CRYP_CFG_KEY);
    CRYP_FIFOFlush(CRYP0);
    CRYP_KeyInit(CRYP0, &AES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * AES-CBC multi block encryption/decryption
 */
#if defined(MBEDTLS_CIPHER_MODE_CBC) && defined(MBEDTLS_AES_CBC_ALT)
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    uint32_t i = 0;
    FlagStatus status = 0;
    uint32_t len;
    uint32_t *pIn;
    uint32_t *pOut;
    uint32_t *IV;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};
    CRYP_IVInitTypeDef AES_CRYP_IVInitStructure = {0};

    if( length % 16 )
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

    pIn = (uint32_t *)input;
    pOut = (uint32_t *)output;
    len = length;

#if defined(MBEDTLS_AES_DMA_ALT)
    CRYP_Dma_Cfg(pIn, len, 0);
#endif

    /* CRYP Initialization Structure */
    AES_CRYP_InitStructure.CRYP_Algo = CRYP_Algo_AES;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_CBC;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_OdatType_8b;
    AES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    AES_CRYP_InitStructure.CRYP_Dout_Cnt = len / 4;
    AES_CRYP_InitStructure.CRYP_Din_Cnt = len / 4;
    AES_CRYP_InitStructure.CRYP_Rlen = len % 16;

    AES_CRYP_InitStructure.CRYP_To_Th = len / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = len / 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = len / 4;

    switch ( ctx->nr ) {
        case 10: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b; break;
        case 12: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b; break;
        case 14: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    IV = ctx->buf;

    for ( i = 0; i < 4; i++ ) {
        IV[i] = __REV(MBEDTLS_GET_UINT32_LE( iv, i << 2 ));
#if defined(MBEDTLS_DEBUG)
        mbedtls_printf("IV[%d]:0x%x\r\n",i,IV[i]);
#endif
    }

    if (mode == MBEDTLS_AES_ENCRYPT) {
        AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Encrypt;
    } else {
        AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Decrypt;
        /* Refresh the iv value when the input length is 16 */
        if (length == 16) {
            memcpy((unsigned char *)iv, (unsigned char *)input, length);
        }
    }

    /* CRYP Initialization Vectors */
    memcpy(AES_CRYP_IVInitStructure.CRYP_IV1, IV, 16);
    CRYP_IVInit(CRYP0, &AES_CRYP_IVInitStructure);

#if defined(MBEDTLS_AES_DMA_ALT)
    /* Crypto Init for CRYP_AlgoDir_Decrypt process */
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);
    CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->CRYP_DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE)) {
            *pOut = CRYP_DataOut(CRYP0);
            pOut += 1;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
    } while (status == RESET);

    CRYP_Cmd(CRYP0, DISABLE);
#else
    while (len >= 16) {
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;

        /* Crypto Init for CRYP_AlgoDir_Decrypt process */
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
        if (len >= 16) {
            /* Write the Input block in the IN FIFO */
            for (i = 0;i < 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            /* Read the Output block from the Output FIFO */
            for (i = 0;i < 4;i++) {
                do {
                    status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
                } while (status == RESET);
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            len = len - 16;
        } else if (len != 0) {
            /* Write the last block in the IN FIFO */
            for (i = 0;i < len / 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            for (i = 0;i < 4 - len / 4;i++) {
                CRYP_DataIn(CRYP0, 0);
            }
            /* Read the Output block from the Output FIFO */
            do {
                status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
            } while (status == RESET);

            for (i = 0;i < 4;i++) {
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            break;
        }
        CRYP_Cmd(CRYP0, DISABLE);
    }
#endif
    if (mode == MBEDTLS_AES_ENCRYPT) {
        /* Refresh the iv value when the input length is 16 */
        if (length == 16) {
            memcpy((unsigned char *)iv, (unsigned char *)output, length);
        }
    }
    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

/*
 * AES-CTR buffer encryption/decryption
 */
#if defined(MBEDTLS_CIPHER_MODE_CTR) && defined(MBEDTLS_AES_CTR_ALT)
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    uint32_t i = 0;
    FlagStatus status = 0;
    uint32_t len;
    uint32_t *counter;
    uint32_t *pIn;
    uint32_t *pOut;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};
    CRYP_IVInitTypeDef AES_CRYP_IVInitStructure = {0};

    if ( length % 16 )
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

    pIn = (uint32_t *)input;
    pOut = (uint32_t *)output;
    len = length;

#if defined(MBEDTLS_AES_DMA_ALT)
    CRYP_Dma_Cfg(pIn, len, 0);
#endif

    /* CRYP Initialization Structure */
    AES_CRYP_InitStructure.CRYP_Algo = CRYP_Algo_AES;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_CTR;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_OdatType_8b;
    AES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    AES_CRYP_InitStructure.CRYP_Dout_Cnt = len / 4;
    AES_CRYP_InitStructure.CRYP_Din_Cnt = len / 4;
    AES_CRYP_InitStructure.CRYP_Rlen = 0;

    AES_CRYP_InitStructure.CRYP_To_Th = len / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = len / 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = len / 4;

    AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Encrypt;

    switch ( ctx->nr ) {
        case 10: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b; break;
        case 12: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b; break;
        case 14: AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    counter = ctx->buf;

    for ( i = 0; i < 4; i++ ) {
        counter[i] = __REV(MBEDTLS_GET_UINT32_LE( nonce_counter, i << 2 ));
#if defined(MBEDTLS_DEBUG)
        mbedtls_printf("counter[%d]:0x%x\r\n",i,counter[i]);
#endif
    }

    /* CTR MODE USE IV0 */
    memcpy(AES_CRYP_IVInitStructure.CRYP_IV0, counter, 16);
    /* CRYP Initialization Vectors */
    CRYP_IVInit(CRYP0, &AES_CRYP_IVInitStructure);

#if defined(MBEDTLS_AES_DMA_ALT)
    /* Crypto Init for CRYP_AlgoDir_Decrypt process */
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);
    CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->CRYP_DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE)) {
            *pOut = CRYP_DataOut(CRYP0);
            pOut += 1;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
    } while (status == RESET);

    CRYP_Cmd(CRYP0, DISABLE);
#else
    while (len > 0) {
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;
        /* Crypto Init for CRYP_AlgoDir_Decrypt process */
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
        if (len >= 16) {
            /* Write the Input block in the IN FIFO */
            for (i = 0;i < 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(input));
                input += 4;
            }
            /* Read the Output block from the Output FIFO */
            for (i = 0;i < 4;i++) {
                do {
                    status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
                } while (status == RESET);
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            len = len - 16;
        } else if (len != 0) {
            /* Write the last block in the IN FIFO */
            for (i = 0;i < len / 4;i++) {
                CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
                pIn += 1;
            }
            for (i = 0;i < 4 - len / 4;i++) {
                CRYP_DataIn(CRYP0, 0);
            }
            /* Read the Output block from the Output FIFO */
            do {
                status = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE);
            } while (status == RESET);

            for (i = 0;i < 4;i++) {
                *pOut = CRYP_DataOut(CRYP0);
                pOut += 1;
            }
            break;
        }
        CRYP_Cmd(CRYP0, DISABLE);
    }
#endif
    return( 0 );
}
#endif

#endif /* MBEDTLS_AES_C */