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

#if defined(MBEDTLS_DES_C)

#include "cryp_alt.h"
#include "mbedtls/des.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"

#include <string.h>

// #define MBEDTLS_DEBUG

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */


/*
 * one DES key set (encryption)
 */
#if defined(MBEDTLS_DES_SET_ONEKEY_EN_ALT)
int mbedtls_des_setkey_enc( mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    unsigned int i;
    uint32_t *SK;
    CRYP_KeyInitTypeDef DES_CRYP_KeyInitStructure = {0};

    /* CRYP key structure init */
    CRYP_KeyStructInit(CRYP0, &DES_CRYP_KeyInitStructure);

    SK = ctx->sk;
    SK[0] = __REV(MBEDTLS_GET_UINT32_LE( key, 0));
    SK[1] = __REV(MBEDTLS_GET_UINT32_LE( key, 4));

    /* CRYP one key init */
    memcpy(DES_CRYP_KeyInitStructure.CRYP_Key, &SK[0], 2 * 4);
    CRYP_KeyInit(CRYP0, &DES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * one DES key set (decryption)
 */
#if defined(MBEDTLS_DES_SET_ONEKEY_DE_ALT)
int mbedtls_des_setkey_dec( mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    unsigned int i;
    uint32_t *SK;
    CRYP_KeyInitTypeDef DES_CRYP_KeyInitStructure = {0};

    /* CRYP key structure init */
    CRYP_KeyStructInit(CRYP0, &DES_CRYP_KeyInitStructure);

    SK = ctx->sk;
    SK[0] = __REV(MBEDTLS_GET_UINT32_LE( key, 0));
    SK[1] = __REV(MBEDTLS_GET_UINT32_LE( key, 4));

    /* CRYP one key init */
    memcpy(DES_CRYP_KeyInitStructure.CRYP_Key, &SK[0], 2 * 4);
    CRYP_KeyInit(CRYP0, &DES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * double DES key set (encryption)
 */
#if defined(MBEDTLS_DES_SET_DOUBLEKEY_EN_ALT)
int mbedtls_des3_set2key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
    unsigned int i;
    uint32_t *SK;
    CRYP_KeyInitTypeDef TDES_CRYP_KeyInitStructure = {0};

    /* CRYP key structure init */
    CRYP_KeyStructInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    SK = ctx->sk;

    for (i = 0;i < 4;i++) {
        SK[i] = __REV(MBEDTLS_GET_UINT32_LE( key, i << 2));
    }
    for (i = 0;i < 2;i++) {
        SK[i + 4] = __REV(MBEDTLS_GET_UINT32_LE( key, i << 2));
    }

    /* CRYP two key init */
    memcpy(TDES_CRYP_KeyInitStructure.CRYP_Key, &SK[0], 6 * 4);
    CRYP_KeyInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * double DES key set (decryption)
 */
#if defined(MBEDTLS_DES_SET_DOUBLEKEY_DE_ALT)
int mbedtls_des3_set2key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
    unsigned int i;
    uint32_t *SK;
    CRYP_KeyInitTypeDef TDES_CRYP_KeyInitStructure = {0};

    /* CRYP key structure init */
    CRYP_KeyStructInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    SK = ctx->sk;

    for (i = 0;i < 4;i++) {
        SK[i] = __REV(MBEDTLS_GET_UINT32_LE( key, i << 2));
    }
    for (i = 0;i < 2;i++) {
        SK[i + 4] = __REV(MBEDTLS_GET_UINT32_LE( key, i << 2));
    }

    /* CRYP double key init */
    memcpy(TDES_CRYP_KeyInitStructure.CRYP_Key, &SK[0], 6 * 4);
    CRYP_KeyInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * triple DES key set (encryption)
 */
#if defined(MBEDTLS_DES_SET_TRIPLEKEY_EN_ALT)
int mbedtls_des3_set3key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
    unsigned int i;
    uint32_t *SK;
    CRYP_KeyInitTypeDef TDES_CRYP_KeyInitStructure = {0};

    /* CRYP key structure init */
    CRYP_KeyStructInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    SK = ctx->sk;

    for (i = 0;i < 6;i++) {
        SK[i] = __REV(MBEDTLS_GET_UINT32_LE( key, 4 * i));
    }

    /* CRYP triple key init */
    memcpy(TDES_CRYP_KeyInitStructure.CRYP_Key, &SK[0], 6 * 4);
    CRYP_KeyInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * triple DES key set (decryption)
 */
#if defined(MBEDTLS_DES_SET_TRIPLEKEY_DE_ALT)
int mbedtls_des3_set3key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
    unsigned int i;
    uint32_t *SK;
    CRYP_KeyInitTypeDef TDES_CRYP_KeyInitStructure = {0};

    /* CRYP key structure init */
    CRYP_KeyStructInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    SK = ctx->sk;

    for (i = 0;i < 6;i++) {
        SK[i] = __REV(MBEDTLS_GET_UINT32_LE( key, 4 * i));
    }

    /* CRYP triple key init */
    memcpy(TDES_CRYP_KeyInitStructure.CRYP_Key, &SK[0], 6 * 4);
    CRYP_KeyInit(CRYP0, &TDES_CRYP_KeyInitStructure);

    return( 0 );
}
#endif

/*
 * DES ECB encryption/decryption
 */
#if defined(MBEDTLS_DES_CRYPT_ECB_MODE_ALT)
int mbedtls_des_crypt_ecb_mode( mbedtls_des_context *ctx,
                                 int mode,
                                 const unsigned char input[8],
                                 unsigned char output[8] )
{
    uint32_t i = 0;
    uint8_t *pIn;
    uint8_t *pOut;
    uint32_t counter = 0;
    FlagStatus status;
    CRYP_InitTypeDef DES_CRYP_InitStructure = {0};

    pIn = (uint8_t *)input;
    pOut = (uint8_t *)output;

    CRYP_Cmd(CRYP0, DISABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_Dma_Cfg(pIn, 8, 0);
#endif

    DES_CRYP_InitStructure.CRYP_Algo = CRYP_RF_CR_ALGO_DES;
    DES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_RF_CR_ALGOMODE_ECB;
    DES_CRYP_InitStructure.CRYP_DataType = CRYP_RF_CR_IDATYPE_BYTE_SWAP;
    DES_CRYP_InitStructure.CRYP_OdatType = CRYP_RF_CR_ODATTYPE_BYTE_SWAP;
    DES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    DES_CRYP_InitStructure.CRYP_Dout_Cnt = 2;
    DES_CRYP_InitStructure.CRYP_Din_Cnt = 2;
    DES_CRYP_InitStructure.CRYP_Rlen = 0;

    DES_CRYP_InitStructure.CRYP_To_Th = 2;
    DES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = 2;
    DES_CRYP_InitStructure.CRYP_Infifo_afull_th = 2;

    if (mode == MBEDTLS_DES_ENCRYPT) {
        DES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_ENCRYPT;
    } else {
        DES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_DECRYPT;
    }

    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);

    CRYP_Init(CRYP0, &DES_CRYP_InitStructure);

    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE)) {
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
    } while (status == RESET);
#else
    /* Write the Input block in the Input FIFO */
    CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
    pIn += 4;
    CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
    pIn += 4;

    /* Wait until the complete message has been processed */
    counter = 0;
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
        counter++;
    } while ((counter != DES_BUSY_TIMEOUT) && (status != RESET));

    if (status != RESET) {
        return CRYP_TIMEOUT_ERR;
    } else {
        /* Read the Output block from the Output FIFO */
        *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
        pOut += 4;
        *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
        pOut += 4;
    }
#endif
    return( 0 );
}
#endif

/*
 * triple DES ECB encryption/decryption
 */
#if defined(MBEDTLS_DES3_CRYPT_ECB_MODE_ALT)
int mbedtls_des3_crypt_ecb_mode( mbedtls_des_context *ctx,
                                 int mode,
                                 const unsigned char input[8],
                                 unsigned char output[8] )
{
    uint32_t i = 0;
    uint8_t *pIn;
    uint8_t *pOut;
    uint32_t counter = 0;
    FlagStatus status;
    CRYP_InitTypeDef TDES_CRYP_InitStructure = {0};

    pIn = (uint8_t *)input;
    pOut = (uint8_t *)output;

    CRYP_Cmd(CRYP0, DISABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_Dma_Cfg(pIn, 8, 0);
#endif

    TDES_CRYP_InitStructure.CRYP_Algo = CRYP_RF_CR_ALGO_TDES;
    TDES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_RF_CR_ALGOMODE_ECB;
    TDES_CRYP_InitStructure.CRYP_DataType = CRYP_RF_CR_IDATYPE_BYTE_SWAP;
    TDES_CRYP_InitStructure.CRYP_OdatType = CRYP_RF_CR_ODATTYPE_BYTE_SWAP;
    TDES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    TDES_CRYP_InitStructure.CRYP_Dout_Cnt = 2;
    TDES_CRYP_InitStructure.CRYP_Din_Cnt = 2;
    TDES_CRYP_InitStructure.CRYP_Rlen = 0;

    TDES_CRYP_InitStructure.CRYP_To_Th = 2;
    TDES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = 2;
    TDES_CRYP_InitStructure.CRYP_Infifo_afull_th = 2;

    if (mode == MBEDTLS_DES_ENCRYPT) {
        TDES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_ENCRYPT;
    } else {
        TDES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_DECRYPT;
    }

    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);

    CRYP_Init(CRYP0, &TDES_CRYP_InitStructure);

    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE)) {
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
    } while (status == RESET);
#else

    /* Write the Input block in the Input FIFO */
    CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
    pIn += 4;
    CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
    pIn += 4;

    /* Wait until the complete message has been processed */
    counter = 0;
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
        counter++;
    } while ((counter != TDES_BUSY_TIMEOUT) && (status != RESET));

    if (status != RESET) {
        return CRYP_TIMEOUT_ERR;
    } else {
        /* Read the Output block from the Output FIFO */
        *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
        pOut += 4;
        *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
        pOut += 4;
    }

#endif
    return( 0 );
}
#endif

/*
 * DES-CBC buffer encryption/decryption
 */
#if defined(MBEDTLS_CIPHER_MODE_CBC) && defined(MBEDTLS_DES_CRYPT_CBC_MODE_ALT)
int mbedtls_des_crypt_cbc( mbedtls_des_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output )
{
    uint32_t i = 0;
    uint32_t len;
    uint8_t *pIn;
    uint8_t *pOut;
    uint32_t *IV;
    __IO uint32_t counter = 0;
    FlagStatus status;
    CRYP_InitTypeDef DES_CRYP_InitStructure = {0};
    CRYP_IVInitTypeDef DES_CRYP_IVInitStructure = {0};

    if ( length % 8 )
        return( MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH );

    len = length;
    pIn = (uint8_t *)input;
    pOut = (uint8_t *)output;

    CRYP_Cmd(CRYP0, DISABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_Dma_Cfg(pIn, len, 0);
#endif

    IV = ctx->sk;
    for ( i = 0; i < 2; i++ ) {
        IV[i] = __REV(MBEDTLS_GET_UINT32_LE( iv, i << 2 ));
    }

    /* CRYP Initialization Vectors */
    memcpy(DES_CRYP_IVInitStructure.CRYP_IV1, IV, 8);
    CRYP_IVInit(CRYP0, &DES_CRYP_IVInitStructure);

    DES_CRYP_InitStructure.CRYP_Algo = CRYP_RF_CR_ALGO_DES;
    DES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_RF_CR_ALGOMODE_CBC;
    DES_CRYP_InitStructure.CRYP_DataType = CRYP_RF_CR_IDATYPE_BYTE_SWAP;
    DES_CRYP_InitStructure.CRYP_OdatType = CRYP_RF_CR_ODATTYPE_BYTE_SWAP;
    DES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    DES_CRYP_InitStructure.CRYP_Dout_Cnt = len / 4;
    DES_CRYP_InitStructure.CRYP_Din_Cnt = len / 4;
    DES_CRYP_InitStructure.CRYP_Rlen = len % 16;

    DES_CRYP_InitStructure.CRYP_To_Th = len / 4;
    DES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = len / 4;
    DES_CRYP_InitStructure.CRYP_Infifo_afull_th = len / 4;

    if (mode == MBEDTLS_DES_ENCRYPT) {
        DES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_ENCRYPT;
    } else {
        DES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_DECRYPT;
        /* Refresh the iv value when the input length is 16 */
        if (length == 8) {
            memcpy((unsigned char *)iv, (unsigned char *)input, length);
        }
    }

    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);

    CRYP_Init(CRYP0, &DES_CRYP_InitStructure);

    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE)) {
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
    } while (status == RESET);
#else
    for (i = 0; i < len; i += 8) {
        /* Write the Input block in the Input FIFO */
        CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
        pIn += 4;
        CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
        pIn += 4;

        /* Wait until the complete message has been processed */
        counter = 0;
        do {
            status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
            counter++;
        } while ((counter != DES_BUSY_TIMEOUT) && (status != RESET));

        if (status != RESET) {
            return CRYP_TIMEOUT_ERR;
        } else {
            /* Read the Output block from the Output FIFO */
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
        }
    }
#endif
    if (mode == MBEDTLS_DES_ENCRYPT) {
        /* Refresh the iv value when the input length is 8 */
        if (length == 8) {
            memcpy((unsigned char *)iv, (unsigned char *)output, length);
        }
    }
    return( 0 );
}
#endif

/*
 * triple DES-CBC buffer encryption/decryption
 */
#if defined(MBEDTLS_CIPHER_MODE_CBC)  && defined(MBEDTLS_DES3_CRYPT_CBC_MODE_ALT)
int mbedtls_des3_crypt_cbc( mbedtls_des3_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output )
{
    uint32_t i = 0;
    uint32_t len;
    uint8_t *pIn;
    uint8_t *pOut;
    uint32_t *IV;
    uint32_t counter = 0;
    FlagStatus status;
    CRYP_InitTypeDef TDES_CRYP_InitStructure = {0};
    CRYP_IVInitTypeDef TDES_CRYP_IVInitStructure = {0};

    if ( length % 8 )
        return( MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH );

    len = length;
    pIn = (uint8_t *)input;
    pOut = (uint8_t *)output;

    CRYP_Cmd(CRYP0, DISABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_Dma_Cfg(pIn, len, 0);
#endif

    IV = ctx->sk;
    for ( i = 0; i < 2; i++ ) {
        IV[i] = __REV(MBEDTLS_GET_UINT32_LE( iv, i << 2 ));
    }

    /* CRYP Vectors init */
    memcpy(TDES_CRYP_IVInitStructure.CRYP_IV1, IV, 8);
    CRYP_IVInit(CRYP0, &TDES_CRYP_IVInitStructure);

    TDES_CRYP_InitStructure.CRYP_Algo = CRYP_RF_CR_ALGO_TDES;
    TDES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_RF_CR_ALGOMODE_CBC;
    TDES_CRYP_InitStructure.CRYP_DataType = CRYP_RF_CR_IDATYPE_BYTE_SWAP;
    TDES_CRYP_InitStructure.CRYP_OdatType = CRYP_RF_CR_ODATTYPE_BYTE_SWAP;
    TDES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    TDES_CRYP_InitStructure.CRYP_Dout_Cnt = len / 4;
    TDES_CRYP_InitStructure.CRYP_Din_Cnt = len / 4;
    TDES_CRYP_InitStructure.CRYP_Rlen = len % 16;

    TDES_CRYP_InitStructure.CRYP_To_Th = len / 4;
    TDES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = len / 4;
    TDES_CRYP_InitStructure.CRYP_Infifo_afull_th = len / 4;

    if (mode == MBEDTLS_DES_ENCRYPT) {
        TDES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_ENCRYPT;
    } else {
        TDES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_DECRYPT;
        /* Refresh the iv value when the input length is 8 */
        if (length == 8) {
            memcpy((unsigned char *)iv, (unsigned char *)input, length);
        }
    }

    /* Flush IN/OUT FIFO */
    CRYP_FIFOFlush(CRYP0);
    CRYP_Init(CRYP0, &TDES_CRYP_InitStructure);

    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);

#if defined(MBEDTLS_DES_DMA_ALT)
    CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
    UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

    /* Read the Output block from the Output FIFO */
    while (CRYP0->DOUT_CNT != 0) {
        if (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE)) {
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
        }
    }

    /* Read the Done flag */
    do {
        status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
    } while (status == RESET);
#else
    for (i = 0; i < len; i += 8) {
        /* Write the Input block in the Input FIFO */
        CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
        pIn += 4;
        CRYP_DataIn(CRYP0, *(uint32_t*)(pIn));
        pIn += 4;

        /* Wait until the complete message has been processed */
        counter = 0;
        do {
            status = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
            counter++;
        } while ((counter != TDES_BUSY_TIMEOUT) && (status != RESET));

        if (status != RESET) {
            return CRYP_TIMEOUT_ERR;
        } else {
            /* Read the Output block from the Output FIFO */
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
            *(uint32_t*)(pOut) = CRYP_DataOut(CRYP0);
            pOut += 4;
        }
    }
#endif
    if (mode == MBEDTLS_DES_ENCRYPT) {
        /* Refresh the iv value when the input length is 8 */
        if (length == 8) {
            memcpy((unsigned char *)iv, (unsigned char *)output, length);
        }
    }
    return( 0 );
}
#endif

#endif /* MBEDTLS_DES_C */