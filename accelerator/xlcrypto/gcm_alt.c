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

#if defined(MBEDTLS_GCM_C)

#include "cryp_alt.h"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

// #define MBEDTLS_DEBUG

#if defined(MBEDTLS_AESNI_C)
#include "aesni.h"
#endif

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#include "mbedtls/platform.h"
#if !defined(MBEDTLS_PLATFORM_C)
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */


/*
 * GCM key set (encryption/decryption)
 */
#if defined(MBEDTLS_AES_GCM_SETKEY_ALT)
int mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (keybits != 128 && keybits != 192 && keybits != 256) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    if (MBEDTLS_CIPHER_ID_AES == cipher) {

        mbedtls_aes_context aes_ctx;
        mbedtls_aes_init( &aes_ctx );

        if (( ret = mbedtls_aes_setkey_enc( &aes_ctx, key, keybits ) ) != 0 ) {
            return( ret );
        }

        ctx->len = (uint64_t)keybits;
        ctx->HL[0] = CRYP_RF_CR_ALGO_AES;
        mbedtls_aes_free( &aes_ctx );
    }
    return( 0 );
}
#endif

/*
 * GCM encryption/decrption (ACRYP GCM mode)
 */
#if defined(MBEDTLS_AES_GCM_CRYPT_ALT)
int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag )
{
    uint32_t i = 0;
    uint32_t headeraddr = (uint32_t)add;
    uint32_t tagaddr = (uint32_t)tag;
    uint32_t inputaddr = (uint32_t)input;
    uint32_t outputaddr = (uint32_t)output;
    uint32_t IV[4];
    uint32_t plainRealLength;
    uint32_t AADRealLength;
    uint32_t keysize;
    uint32_t algo;
    uint32_t loopcounter = 0;
    uint32_t counter = 0;
    FlagStatus busystatus = 0;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};
    CRYP_IVInitTypeDef AES_CRYP_IVInitStructure = {0};

    /* header length in bits */
    uint64_t headerlength = add_len * 8;
    /* input length in bits */
    uint64_t inputlength = length * 8;

    if (length % 16) {
        plainRealLength = length - (length % 16) + 16;
    } else {
        plainRealLength = length;
    }

    if (add_len % 16) {
        AADRealLength = add_len - (add_len % 16) + 16;
    } else {
        AADRealLength = add_len;
    }

    keysize = (uint32_t)ctx->len;
    algo = (uint32_t)ctx->HL[0];

    if ( tag_len > 16 || tag_len < 4 )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    /* IV is limited to 2^64 bits, so 2^61 bytes */
    /* IV is not allowed to be zero length */
    if ( iv_len == 0 || (uint64_t) iv_len >> 61 != 0 )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    if ( iv_len == 12 ) {
        IV[3] = 1;
    } else {
        mbedtls_printf("CRYP GCM only support IV LENGTH 12 \r\n");
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    /* CRYP Initialization Vectors */
    for ( i = 0; i < 3; i++ ) {
        IV[i] = __REV(MBEDTLS_GET_UINT32_LE( iv, i << 2 ));
    }
    /* CRYP Initialization Vectors */
    memcpy(AES_CRYP_IVInitStructure.CRYP_IV0, &IV[0], 16);
    CRYP_IVInit(CRYP0, &AES_CRYP_IVInitStructure);

    /* CRYP Initialization Structure */
    AES_CRYP_InitStructure.CRYP_Algo = algo;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_RF_CR_ALGOMODE_GCM;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_RF_CR_IDATYPE_BYTE_SWAP;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_RF_CR_ODATTYPE_BYTE_SWAP;
    AES_CRYP_InitStructure.CRYP_Gcm_Ccmph = UNUSED;

    AES_CRYP_InitStructure.CRYP_Rlen = length % 16;
    AES_CRYP_InitStructure.CRYP_To_Th = length / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = 4;

    switch (keysize) {
        case 128:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_RF_CR_KEYSIZE_128BIT;
            break;
        case 192:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_RF_CR_KEYSIZE_192BIT;
            break;
        case 256:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_RF_CR_KEYSIZE_256BIT;
            break;
        default:
        break;
    }

    /*------------------------- CRYP_RF_CR_ALGODIR_ENCRYPT -------------------------*/
    if(mode == MBEDTLS_GCM_ENCRYPT)
    {
        /* Crypto Init for Key preparation for decryption process */
        AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_RF_CR_ALGODIR_ENCRYPT;
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);

    /***************************** Init phase *********************************/
        /* Select init phase */
        CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_INIT_PH);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
        while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY) == 1) {}
        /* Disable Crypto processor */
        CRYP_Cmd(CRYP0, DISABLE);
    /***************************** header phase *******************************/
        if (AADRealLength != 0) {
        #if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_Dma_Cfg((uint32_t*)(headeraddr), AADRealLength, 0);
        #endif
            AES_CRYP_InitStructure.CRYP_Dout_Cnt = 0;
            AES_CRYP_InitStructure.CRYP_Din_Cnt = AADRealLength / 4;
            CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
            /* Select header phase */
            CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_AAD_PH);
            /* Enable Crypto processor */
            CRYP_Cmd(CRYP0, ENABLE);
        #if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
            UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

            /* Read the Done flag */
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
            } while (busystatus == RESET);
        #else
            for (loopcounter = 0; (loopcounter < AADRealLength); loopcounter += 16) {
                /* Wait until the IFEM flag is reset */
                while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_IFEM) == RESET) {}
                /* Write the Input block in the IN FIFO */
                for ( i = 0; i < 4; i++ ) {
                    CRYP_DataIn(CRYP0, *(uint32_t*)(headeraddr));
                    headeraddr += 4;
                }
            }

            /* Wait until the complete message has been processed */
            counter = 0;
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
                counter++;
            } while ((counter != GCM_BUSY_TIMEOUT) && (busystatus != RESET));

            if (busystatus != RESET) {
                return CRYP_TIMEOUT_ERR;
            }
        #endif
            /* Disable Crypto processor */
            CRYP_Cmd(CRYP0, DISABLE);
        }
    /***************************** payload phase ******************************/
        if (plainRealLength != 0) {
        #if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_Dma_Cfg((uint32_t*)(inputaddr), plainRealLength, 0);
        #endif
            AES_CRYP_InitStructure.CRYP_Dout_Cnt = plainRealLength / 4;
            AES_CRYP_InitStructure.CRYP_Din_Cnt = plainRealLength / 4;
            CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
            /* Select payload phase */
            CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_PAYLOAD_PH);
            /* Enable Crypto processor */
            CRYP_Cmd(CRYP0, ENABLE);

        #if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
            UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

            /* Read the Output block from the Output FIFO */
            while (CRYP0->DOUT_CNT != 0) {
                if (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE)) {
                    *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0);
                    outputaddr += 4;
                }
            }
            /* Read the Done flag */
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
            } while (busystatus == RESET);
        #else
            for (loopcounter = 0; loopcounter < plainRealLength; loopcounter += 16) {
                /* Wait until the IFEM flag is reset */
                while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_IFEM) == RESET) {}
                /* Write the Input block in the IN FIFO */
                for ( i = 0; i < 4; i++ ) {
                    CRYP_DataIn(CRYP0, *(uint32_t*)(inputaddr));
                    inputaddr += 4;
                }
                /* Wait until the complete message has been processed */
                counter = 0;
                do {
                    busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
                    counter++;
                } while ((counter != GCM_BUSY_TIMEOUT) && (busystatus != RESET));

                if (busystatus != RESET) {
                    return CRYP_TIMEOUT_ERR;
                } else {
                    /* Wait until the OFNE flag is reset */
                    while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE) == RESET) {}
                    /* Read the Output block from the Output FIFO */
                    for ( i = 0; i < 4; i++ ) {
                        *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0);
                        outputaddr += 4;
                    }
                }
                while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY) == 1) {}
            }
        #endif
            /* Disable Crypto processor */
            CRYP_Cmd(CRYP0, DISABLE);
        }
    /***************************** final phase ********************************/
        /* CRYP Initialization Vectors */
        CRYP_IVInit_GCM_CCM(CRYP0, &AES_CRYP_IVInitStructure);

        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Select final phase */
        CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_FINAL_PH);

        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);

        /* Wait until the IFEM flag is reset */
        while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_IFEM) == RESET) {}

        /* Write number of bits concatenated with header in the IN FIFO */
        CRYP_DataIn(CRYP0, __REV(headerlength >> 32));
        CRYP_DataIn(CRYP0, __REV(headerlength));
        CRYP_DataIn(CRYP0, __REV(inputlength >> 32));
        CRYP_DataIn(CRYP0, __REV(inputlength));

        /* Wait until the OFNE flag is reset */
        while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE) == RESET) {}

        /* Read the Auth TAG in the OUT FIFO */
        for( i = 0; i < 4; i++ ) {
            *(uint32_t*)(tagaddr) = CRYP_DataOut(CRYP0);
            tagaddr += 4;
        }
    /*------------------------- CRYP_RF_CR_ALGODIR_DECRYPT -------------------------*/
    } else {
        /* Crypto Init for Key preparation for decryption process */
        AES_CRYP_InitStructure.CRYP_AlgoDir  = CRYP_RF_CR_ALGODIR_DECRYPT;
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);

    /****************************** Init phase ********************************/
        /* Select init phase */
        CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_INIT_PH);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
        while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY) == 1) {}
        /* Disable Crypto processor */
        CRYP_Cmd(CRYP0, DISABLE);
    /***************************** header phase *******************************/
        if (AADRealLength != 0) {
        #if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_Dma_Cfg((uint32_t*)(headeraddr), AADRealLength, 0);
        #endif
            AES_CRYP_InitStructure.CRYP_Dout_Cnt = 0;
            AES_CRYP_InitStructure.CRYP_Din_Cnt = AADRealLength / 4;
            CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
            /* Select header phase */
            CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_AAD_PH);
            /* Enable Crypto processor */
            CRYP_Cmd(CRYP0, ENABLE);

		#if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
            UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

            /* Read the Done flag */
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
            } while (busystatus == RESET);
        #else
            for (loopcounter = 0; (loopcounter < AADRealLength); loopcounter += 16) {
                /* Wait until the IFEM flag is reset */
                while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_IFEM) == RESET) {}
                /* Write the Input block in the IN FIFO */
                for ( i = 0; i < 4; i++ ) {
                    CRYP_DataIn(CRYP0, *(uint32_t*)(headeraddr));
                    headeraddr += 4;
                }
            }

            /* Wait until the complete message has been processed */
            counter = 0;
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
                counter++;
            } while ((counter != GCM_BUSY_TIMEOUT) && (busystatus != RESET));

            if (busystatus != RESET) {
                return CRYP_TIMEOUT_ERR;
            }
        #endif
            CRYP_Cmd(CRYP0, DISABLE);
        }
    /****************************** payload phase *****************************/
        if (plainRealLength != 0) {
        #if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_Dma_Cfg((uint32_t*)(inputaddr), plainRealLength, 0);
        #endif
            AES_CRYP_InitStructure.CRYP_Dout_Cnt = plainRealLength / 4;
            AES_CRYP_InitStructure.CRYP_Din_Cnt = plainRealLength / 4;
            CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
            /* Select payload phase */
            CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_PAYLOAD_PH);
            /* Enable Crypto processor */
            CRYP_Cmd(CRYP0, ENABLE);
        #if defined(MBEDTLS_GCM_DMA_ALT)
            CRYP_DMACmd(CRYP0, CRYP_RF_DMAEN_DIEN, ENABLE);
            UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

            /* Read the Output block from the Output FIFO */
            while (CRYP0->DOUT_CNT != 0) {
                if (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE)) {
                    *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0);
                    outputaddr += 4;
                }
            }
            /* Read the Done flag */
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_DONE);
            } while (busystatus == RESET);
        #else
            for (loopcounter = 0; loopcounter < plainRealLength; loopcounter += 16) {
                /* Wait until the IFEM flag is reset */
                while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_IFEM) == RESET) {}
                /* Write the Input block in the IN FIFO */
                for ( i = 0; i < 4; i++ ) {
                    CRYP_DataIn(CRYP0, *(uint32_t*)(inputaddr));
                    inputaddr += 4;
                }
                /* Wait until the complete message has been processed */
                counter = 0;
                do {
                    busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_CORE_BUSY);
                    counter++;
                } while ((counter != GCM_BUSY_TIMEOUT) && (busystatus != RESET));

                if (busystatus != RESET) {
                    return CRYP_TIMEOUT_ERR;
                } else {
                    /* Wait until the OFNE flag is reset */
                    while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE) == RESET) {}
                    /* Read the Output block from the Output FIFO */
                    for ( i = 0; i < 4; i++ ) {
                        *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0 );
                        outputaddr += 4;
                    }
                }
                while (CRYP_GetFlagStatus(CRYP0,CRYP_RF_SR_CORE_BUSY) == 1) {}
            }
        #endif
            /* Disable Crypto processor */
            CRYP_Cmd(CRYP0, DISABLE);
        }
    /****************************** final phase *******************************/
        /* CRYP Initialization Vectors */
        CRYP_IVInit_GCM_CCM(CRYP0, &AES_CRYP_IVInitStructure);

        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = 4;
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);

        /* Select final phase */
        CRYP_PhaseConfig(CRYP0, CRYP_RF_CR_GCM_CCMPH_FINAL_PH);

        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);

        /* Wait until the IFEM flag is reset */
        while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_IFEM) == RESET) {}

        /* Write number of bits concatenated with header in the IN FIFO */
        CRYP_DataIn(CRYP0, __REV(headerlength >> 32));
        CRYP_DataIn(CRYP0, __REV(headerlength));
        CRYP_DataIn(CRYP0, __REV(inputlength >> 32));
        CRYP_DataIn(CRYP0, __REV(inputlength));

        /* Wait until the OFNE flag is reset */
        while (CRYP_GetFlagStatus(CRYP0, CRYP_RF_SR_OFNE) == RESET) {}

        /* Read the Auth TAG in the OUT FIFO */
        for ( i = 0; i < 4; i++ ) {
            *(uint32_t*)(tagaddr) = CRYP_DataOut(CRYP0);
            tagaddr += 4;
        }
    }
    /* Disable Crypto processor */
    CRYP_Cmd(CRYP0, DISABLE);
    return 0;
}
#endif /* MBEDTLS_AES_GCM_CRYPT_ALT */


#endif /* MBEDTLS_GCM_C */