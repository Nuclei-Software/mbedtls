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

#if defined(MBEDTLS_CCM_C)

#include "cryp_alt.h"
#include "mbedtls/ccm.h"
#include "mbedtls/aes.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

// #define MBEDTLS_DEBUG

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */
#endif /* MBEDTLS_PLATFORM_C */



/*
 * CCM key set (encryption/decryption)
 */
#if defined(MBEDTLS_AES_CCM_SETKEY_ALT)
int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ctx == NULL )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    if (MBEDTLS_CIPHER_ID_AES == cipher) {

        mbedtls_aes_context aes_ctx;
        mbedtls_aes_init( &aes_ctx );

        if (( ret = mbedtls_aes_setkey_enc( &aes_ctx, key, keybits ) ) != 0 ) {
            return( ret );
        }

        ctx->tag_len = (size_t) keybits;
        ctx->processed = (size_t) CRYP_Algo_AES;
        mbedtls_aes_free( &aes_ctx );
    }
    return( 0 );
}
#endif

/*
 * CCM encryption (ACRYP CCM mode)
 */
#if defined(MBEDTLS_AES_CCM_ENCRYPT_ALT)
int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
    uint32_t counter = 0;
    FlagStatus busystatus = 0;
    uint32_t keysize;
    uint32_t algo;
    uint32_t inputaddr  = (uint32_t)input;
    uint32_t outputaddr = (uint32_t)output;
    uint32_t headeraddr = (uint32_t)add;
    uint32_t tagaddr = (uint32_t)tag;
    uint32_t headersize = add_len;
    uint32_t headersizeRlen = 0;
    uint8_t *HBuffer;
    uint32_t plainRealLength = 0;
    uint32_t loopcounter = 0;
    uint32_t bufferidx = 0;
    uint8_t blockb0[16] = {0};
    uint8_t ctr[16] = {0};
    uint32_t temptag[4] = {0};
    uint32_t ctraddr = (uint32_t)ctr;
    uint32_t b0addr = (uint32_t)blockb0;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};
    CRYP_IVInitTypeDef AES_CRYP_IVInitStructure = {0};

    /* Temporary buffer used to append the header.HBuffer size must be equal to HEADER_SIZE + 21 */
    if (headersize != 0) {
        if( ( HBuffer = (uint8_t *)mbedtls_calloc( headersize + 21, sizeof(uint8_t) ) ) == NULL )
            return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

    keysize = (uint32_t)ctx->tag_len;
    algo = (uint32_t)ctx->processed;

    AES_CRYP_InitStructure.CRYP_Algo = algo;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_CCM;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_OdatType_8b;

    AES_CRYP_InitStructure.CRYP_To_Th = length / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = 4;

    if (length % 16) {
        plainRealLength = length - (length % 16) + 16;
    } else {
        plainRealLength = length;
    }

  /************************ Formatting the header block ***********************/
    if (headersize != 0) {
        if (headersize % 16) {
            headersizeRlen = headersize % 16;
        }

        /* Check that the associated data (or header) length is lower than 2^16 - 2^8 = 65536 - 256 = 65280 */
        if (headersize < 65280) {
            HBuffer[bufferidx++] = (uint8_t) ((headersize >> 8) & 0xFF);
            HBuffer[bufferidx++] = (uint8_t) ((headersize) & 0xFF);
            headersize += 2;
            headersizeRlen += 2;
        } else {
            /* header is encoded as 0xff || 0xfe || [headersize]32, i.e., six octets */
            HBuffer[bufferidx++] = 0xFF;
            HBuffer[bufferidx++] = 0xFE;
            HBuffer[bufferidx++] = headersize & 0xff000000;
            HBuffer[bufferidx++] = headersize & 0x00ff0000;
            HBuffer[bufferidx++] = headersize & 0x0000ff00;
            HBuffer[bufferidx++] = headersize & 0x000000ff;
            headersize += 6;
            headersizeRlen += 6;
        }
        /* Copy the header buffer in internal buffer "HBuffer" */
        for (loopcounter = 0; loopcounter < headersize; loopcounter++) {
            HBuffer[bufferidx++] = add[loopcounter];
        }
        /* Check if the header size is modulo 16 */
        if ((headersize % 16) != 0) {
            /* Padd the header buffer with 0s till the HBuffer length is modulo 16 */
            for (loopcounter = headersize; loopcounter <= ((headersize/16) + 1) * 16; loopcounter++) {
                HBuffer[loopcounter] = 0;
            }
            /* Set the header size to modulo 16 */
            headersize = ((headersize/16) + 1) * 16;
        }
        /* set the pointer headeraddr to HBuffer */
        headeraddr = (uint32_t)HBuffer;
    }
  /************************* Formatting the block B0 **************************/
    if (headersize != 0) {
        blockb0[0] = 0x40;
    }
    /* Flags byte */
    blockb0[0] |= 0u | (((( (uint8_t) tag_len - 2) / 2) & 0x07 ) << 3 ) | ( ( (uint8_t) (15 - iv_len) - 1) & 0x07);

    for (loopcounter = 0; loopcounter < iv_len; loopcounter++) {
        blockb0[loopcounter+1] = iv[loopcounter];
    }
    for ( ; loopcounter < 13; loopcounter++) {
        blockb0[loopcounter+1] = 0;
    }

    blockb0[14] = ((length >> 8) & 0xFF);
    blockb0[15] = (length & 0xFF);
    /************************* Formatting the initial counter *******************/
    /* Byte 0:
        Bits 7 and 6 are reserved and shall be set to 0
        Bits 3, 4, and 5 shall also be set to 0, to ensure that all the counter blocks
        are distinct from B0
        Bits 0, 1, and 2 contain the same encoding of q as in B0
    */
    ctr[0] = blockb0[0] & 0x07;
    /* byte 1 to iv_len is the IV (Nonce) */
    for (loopcounter = 1; loopcounter < iv_len + 1; loopcounter++) {
        ctr[loopcounter] = blockb0[loopcounter];
    }
    /* Set the LSB to 1 */
    // ctr[15] |= 0x01;         //ctr1
    ctr[15] = 0x00;             //ctr0

    switch (keysize) {
        case 128:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b;
            break;
        case 192:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b;
            break;
        case 256:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b;
            break;
        default:
            break;
    }

    /* CRYP Initialization Vectors */
    AES_CRYP_IVInitStructure.CRYP_IV0[0] = (__REV(*(uint32_t*)(ctraddr)));
    ctraddr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV0[1] = (__REV(*(uint32_t*)(ctraddr)));
    ctraddr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV0[2] = (__REV(*(uint32_t*)(ctraddr)));
    ctraddr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV0[3] = (__REV(*(uint32_t*)(ctraddr)));

    b0addr = (uint32_t)blockb0;
    AES_CRYP_IVInitStructure.CRYP_IV1[0] = (__REV(*(uint32_t*)(b0addr)));
    b0addr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV1[1] = (__REV(*(uint32_t*)(b0addr)));
    b0addr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV1[2] = (__REV(*(uint32_t*)(b0addr)));
    b0addr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV1[3] = (__REV(*(uint32_t*)(b0addr)));

  /*------------------ AES CRYP_AlgoDir_Encrypt ------------------*/
    /* CRYP Initialization Vectors */
    CRYP_IVInit(CRYP0, &AES_CRYP_IVInitStructure);

    /* Crypto Init for Key preparation for decryption process */
    AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Encrypt;
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);

    /***************************** Init phase *********************************/
    /* Select init phase */
    CRYP_PhaseConfig(CRYP0, CRYP_Initial_PH1);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);
    while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_BUSY) == 1) {}
    /* Disable Crypto processor */
    CRYP_Cmd(CRYP0, DISABLE);
    /***************************** header phase *******************************/
    if (headersize != 0) {
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 0;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = headersize / 4;
        AES_CRYP_InitStructure.CRYP_Rlen = headersizeRlen;
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_Dma_Cfg((uint32_t*)(headeraddr), headersize, 0);
    #endif
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Select header phase */
        CRYP_PhaseConfig(CRYP0, CRYP_ADD_PH2);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
        UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

        /* Read the Done flag */
        do {
            busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
        } while (busystatus == RESET);
    #else
        for (loopcounter = 0; loopcounter < headersize; loopcounter += 16) {
            /* Wait until the IFEM flag is reset */
            while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_IFEM) == RESET) {}

            /* Write the input block in the IN FIFO */
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
        }

        /* Wait until the complete message has been processed */
        counter = 0;
        do {
            busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_BUSY);
            counter++;
        } while ((counter != CCM_BUSY_TIMEOUT) && (busystatus != RESET));

        if (busystatus != RESET) {
            return CRYP_TIMEOUT_ERR;
        }
    #endif
        CRYP_Cmd(CRYP0, DISABLE);
    }
    /**************************** payload phase *******************************/
    if (plainRealLength != 0) {
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_Dma_Cfg((uint32_t*)(inputaddr), plainRealLength, 0);
    #endif
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = plainRealLength / 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = plainRealLength / 4;
        AES_CRYP_InitStructure.CRYP_Rlen = length % 16;
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Select payload phase */
        CRYP_PhaseConfig(CRYP0, CRYP_Text_PH3);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
        UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

        /* Read the Output block from the Output FIFO */
        while (CRYP0->CRYP_DOUT_CNT != 0) {
            if (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE)) {
                *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0);
                outputaddr += 4;
            }
        }
        /* Read the Done flag */
        do {
            busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
        } while (busystatus == RESET);
    #else
        for (loopcounter = 0; loopcounter < plainRealLength; loopcounter += 16) {
            /* Wait until the IFEM flag is reset */
            while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_IFEM) == RESET) {}

            /* Write the input block in the IN FIFO */
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;

            /* Wait until the complete message has been processed */
            counter = 0;
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_BUSY);
                counter++;
            } while ((counter != CCM_BUSY_TIMEOUT) && (busystatus != RESET));

            if (busystatus != RESET) {
                return CRYP_TIMEOUT_ERR;
            } else {
                /* Wait until the OFNE flag is reset */
                while (CRYP_GetFlagStatus(CRYP0,CRYP_FLAG_OFNE) == RESET) {}
                for(uint16_t i = 0; i < 4; i++ ) {
                    *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0);
                    outputaddr+=4;
                }
            }
            while (CRYP_GetFlagStatus(CRYP0,CRYP_FLAG_BUSY) == 1) {}
        }
    #endif
        CRYP_Cmd(CRYP0, DISABLE);
    }
    /***************************** final phase ********************************/
    /*final phase IV config IV0 */
    CRYP_IVInit_GCM_CCM(CRYP0, &AES_CRYP_IVInitStructure);

    AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
    AES_CRYP_InitStructure.CRYP_Din_Cnt = 0;
    AES_CRYP_InitStructure.CRYP_Rlen = 0;
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
    /* Select final phase */
    CRYP_PhaseConfig(CRYP0, CRYP_Final_PH);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);

    /* Wait until the OFNE flag is reset */
    while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE) == RESET) {}

    /* Read the Auth TAG in the IN FIFO */
    temptag[0] = CRYP_DataOut(CRYP0);
    temptag[1] = CRYP_DataOut(CRYP0);
    temptag[2] = CRYP_DataOut(CRYP0);
    temptag[3] = CRYP_DataOut(CRYP0);

    /* Disable Crypto processor */
    CRYP_Cmd(CRYP0, DISABLE);

    /* Copy temporary authentication TAG in user TAG buffer */
    for (loopcounter = 0; loopcounter < tag_len; loopcounter++) {
        /* Set the authentication TAG buffer */
        *((uint8_t*)tagaddr + loopcounter) = *((uint8_t*)temptag + loopcounter);
    }
    if (headersize != 0) {
        mbedtls_free(HBuffer);
    }
    return 0;
}
#endif

/*
 * CCM decryption (ACRYP CCM mode)
 */
#if defined(MBEDTLS_AES_CCM_DECRYPT_ALT)
int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
    uint32_t counter = 0;
    FlagStatus busystatus = 0;
    uint32_t keysize;
    uint32_t algo;
    uint32_t inputaddr  = (uint32_t)input;
    uint32_t outputaddr = (uint32_t)output;
    uint32_t headeraddr = (uint32_t)add;
    uint32_t tagaddr = (uint32_t)tag;
    uint32_t headersize = add_len;
    uint32_t headersizeRlen = 0;
    uint8_t *HBuffer;
    uint32_t plainRealLength = 0;
    uint32_t loopcounter = 0;
    uint32_t bufferidx = 0;
    uint8_t blockb0[16] = {0};
    uint8_t ctr[16] = {0};
    uint32_t temptag[4] = {0};
    uint32_t ctraddr = (uint32_t)ctr;
    uint32_t b0addr = (uint32_t)blockb0;
    CRYP_InitTypeDef AES_CRYP_InitStructure = {0};
    CRYP_IVInitTypeDef AES_CRYP_IVInitStructure = {0};

    /* Temporary buffer used to append the header.HBuffer size must be equal to HEADER_SIZE + 21 */
    if (headersize != 0) {
        if( ( HBuffer = (uint8_t *)mbedtls_calloc( headersize + 21, sizeof(uint8_t) ) ) == NULL )
            return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

    keysize = (uint32_t)ctx->tag_len;
    algo = (uint32_t)ctx->processed;

    AES_CRYP_InitStructure.CRYP_Algo = algo;
    AES_CRYP_InitStructure.CRYP_AlgoMode = CRYP_AlgoMode_CCM;
    AES_CRYP_InitStructure.CRYP_DataType = CRYP_DataType_8b;
    AES_CRYP_InitStructure.CRYP_OdatType = CRYP_OdatType_8b;

    AES_CRYP_InitStructure.CRYP_To_Th = length / 4;
    AES_CRYP_InitStructure.CRYP_Ofifo_aempty_th = 4;
    AES_CRYP_InitStructure.CRYP_Infifo_afull_th = 4;

    if (length % 16) {
        plainRealLength = length - (length % 16) + 16;
    } else {
        plainRealLength = length;
    }

  /************************ Formatting the header block ***********************/
    if (headersize != 0) {
        if (headersize % 16) {
            headersizeRlen = headersize % 16;
        }

        /* Check that the associated data (or header) length is lower than 2^16 - 2^8 = 65536 - 256 = 65280 */
        if (headersize < 65280) {
            HBuffer[bufferidx++] = (uint8_t) ((headersize >> 8) & 0xFF);
            HBuffer[bufferidx++] = (uint8_t) ((headersize) & 0xFF);
            headersize += 2;
            headersizeRlen += 2;
        } else {
            /* header is encoded as 0xff || 0xfe || [headersize]32, i.e., six octets */
            HBuffer[bufferidx++] = 0xFF;
            HBuffer[bufferidx++] = 0xFE;
            HBuffer[bufferidx++] = headersize & 0xff000000;
            HBuffer[bufferidx++] = headersize & 0x00ff0000;
            HBuffer[bufferidx++] = headersize & 0x0000ff00;
            HBuffer[bufferidx++] = headersize & 0x000000ff;
            headersize += 6;
            headersizeRlen += 6;
        }
        /* Copy the header buffer in internal buffer "HBuffer" */
        for (loopcounter = 0; loopcounter < headersize; loopcounter++) {
            HBuffer[bufferidx++] = add[loopcounter];
        }
        /* Check if the header size is modulo 16 */
        if ((headersize % 16) != 0) {
            /* Padd the header buffer with 0s till the HBuffer length is modulo 16 */
            for (loopcounter = headersize; loopcounter <= ((headersize/16) + 1) * 16; loopcounter++) {
                HBuffer[loopcounter] = 0;
            }
            /* Set the header size to modulo 16 */
            headersize = ((headersize/16) + 1) * 16;
        }
        /* set the pointer headeraddr to HBuffer */
        headeraddr = (uint32_t)HBuffer;
    }
  /************************* Formatting the block B0 **************************/
    if (headersize != 0) {
        blockb0[0] = 0x40;
    }
    /* Flags byte */
    blockb0[0] |= 0u | (((( (uint8_t) tag_len - 2) / 2) & 0x07 ) << 3 ) | ( ( (uint8_t) (15 - iv_len) - 1) & 0x07);

    for (loopcounter = 0; loopcounter < iv_len; loopcounter++) {
        blockb0[loopcounter+1] = iv[loopcounter];
    }
    for ( ; loopcounter < 13; loopcounter++) {
        blockb0[loopcounter+1] = 0;
    }

    blockb0[14] = ((length >> 8) & 0xFF);
    blockb0[15] = (length & 0xFF);
    /************************* Formatting the initial counter *******************/
    /* Byte 0:
        Bits 7 and 6 are reserved and shall be set to 0
        Bits 3, 4, and 5 shall also be set to 0, to ensure that all the counter blocks
        are distinct from B0
        Bits 0, 1, and 2 contain the same encoding of q as in B0
    */
    ctr[0] = blockb0[0] & 0x07;
    /* byte 1 to iv_len is the IV (Nonce) */
    for (loopcounter = 1; loopcounter < iv_len + 1; loopcounter++) {
        ctr[loopcounter] = blockb0[loopcounter];
    }
    /* Set the LSB to 1 */
    // ctr[15] |= 0x01;         //ctr1
    ctr[15] = 0x00;             //ctr0

    switch (keysize) {
        case 128:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_128b;
            break;
        case 192:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_192b;
            break;
        case 256:
            AES_CRYP_InitStructure.CRYP_KeySize = CRYP_KeySize_256b;
            break;
        default:
            break;
    }

    /* CRYP Initialization Vectors */
    AES_CRYP_IVInitStructure.CRYP_IV0[0] = (__REV(*(uint32_t*)(ctraddr)));
    ctraddr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV0[1] = (__REV(*(uint32_t*)(ctraddr)));
    ctraddr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV0[2] = (__REV(*(uint32_t*)(ctraddr)));
    ctraddr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV0[3] = (__REV(*(uint32_t*)(ctraddr)));

    b0addr = (uint32_t)blockb0;
    AES_CRYP_IVInitStructure.CRYP_IV1[0] = (__REV(*(uint32_t*)(b0addr)));
    b0addr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV1[1] = (__REV(*(uint32_t*)(b0addr)));
    b0addr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV1[2] = (__REV(*(uint32_t*)(b0addr)));
    b0addr += 4;
    AES_CRYP_IVInitStructure.CRYP_IV1[3] = (__REV(*(uint32_t*)(b0addr)));

  /*------------------ AES CRYP_AlgoDir_Decrypt ------------------*/
    /* CRYP Initialization Vectors */
    CRYP_IVInit(CRYP0, &AES_CRYP_IVInitStructure);

    /* Crypto Init for Key preparation for decryption process */
    AES_CRYP_InitStructure.CRYP_AlgoDir = CRYP_AlgoDir_Decrypt;
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);

    /***************************** Init phase *********************************/
    /* Select init phase */
    CRYP_PhaseConfig(CRYP0, CRYP_Initial_PH1);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);
    while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_BUSY) == 1) {}
    /* Disable Crypto processor */
    CRYP_Cmd(CRYP0, DISABLE);
    /***************************** header phase *******************************/
    if (headersize != 0) {
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_Dma_Cfg((uint32_t*)(headeraddr), headersize, 0);
    #endif
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = 0;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = headersize / 4;
        AES_CRYP_InitStructure.CRYP_Rlen = headersizeRlen;
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Select header phase */
        CRYP_PhaseConfig(CRYP0, CRYP_ADD_PH2);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
        UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

        /* Read the Done flag */
        do {
            busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
        } while (busystatus == RESET);
    #else
        for (loopcounter = 0; loopcounter < headersize; loopcounter += 16) {
            /* Wait until the IFEM flag is reset */
            while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_IFEM) == RESET) {}

            /* Write the input block in the IN FIFO */
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(headeraddr));
            headeraddr += 4;
        }

        /* Wait until the complete message has been processed */
        counter = 0;
        do {
            busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_BUSY);
            counter++;
        } while ((counter != CCM_BUSY_TIMEOUT) && (busystatus != RESET));

        if (busystatus != RESET) {
            return CRYP_TIMEOUT_ERR;
        }
    #endif
        CRYP_Cmd(CRYP0, DISABLE);
    }
    /**************************** payload phase *******************************/
    if (plainRealLength != 0) {
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_Dma_Cfg((uint32_t*)(inputaddr), plainRealLength, 0);
    #endif
        AES_CRYP_InitStructure.CRYP_Dout_Cnt = plainRealLength / 4;
        AES_CRYP_InitStructure.CRYP_Din_Cnt = plainRealLength / 4;
        AES_CRYP_InitStructure.CRYP_Rlen = length % 16;
        CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
        /* Select payload phase */
        CRYP_PhaseConfig(CRYP0, CRYP_Text_PH3);
        /* Enable Crypto processor */
        CRYP_Cmd(CRYP0, ENABLE);
    #if defined(MBEDTLS_CCM_DMA_ALT)
        CRYP_DMACmd(CRYP0, CRYP_DIEN, ENABLE);
        UDMA_Cmd(CRYP0_TX_DMA_DMA_CH, ENABLE);

        /* Read the Output block from the Output FIFO */
        while (CRYP0->CRYP_DOUT_CNT != 0) {
            if (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE)) {
                *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0);
                outputaddr += 4;
            }
        }
        /* Read the Done flag */
        do {
            busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_DONE);
        } while (busystatus == RESET);
    #else
        for (loopcounter = 0; loopcounter < plainRealLength; loopcounter += 16) {
            /* Wait until the IFEM flag is reset */
            while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_IFEM) == RESET) {}

            /* Write the input block in the IN FIFO */
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;
            CRYP_DataIn(CRYP0,*(uint32_t*)(inputaddr));
            inputaddr += 4;

            /* Wait until the complete message has been processed */
            counter = 0;
            do {
                busystatus = CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_BUSY);
                counter++;
            } while ((counter != CCM_BUSY_TIMEOUT) && (busystatus != RESET));

            if (busystatus != RESET) {
                return CRYP_TIMEOUT_ERR;
            } else {
                /* Wait until the OFNE flag is reset */
                while (CRYP_GetFlagStatus(CRYP0,CRYP_FLAG_OFNE) == RESET) {}
                for(uint16_t i = 0; i < 4; i++ ) {
                    *(uint32_t*)(outputaddr) = CRYP_DataOut(CRYP0);
                    outputaddr+=4;
                }
            }
            while (CRYP_GetFlagStatus(CRYP0,CRYP_FLAG_BUSY) == 1) {}
        }
    #endif
        CRYP_Cmd(CRYP0, DISABLE);
    }
    /***************************** final phase ********************************/
    /*final phase IV config IV0 */
    CRYP_IVInit_GCM_CCM(CRYP0, &AES_CRYP_IVInitStructure);

    AES_CRYP_InitStructure.CRYP_Dout_Cnt = 4;
    AES_CRYP_InitStructure.CRYP_Din_Cnt = 0;
    AES_CRYP_InitStructure.CRYP_Rlen = 0;
    CRYP_Init(CRYP0, &AES_CRYP_InitStructure);
    /* Select final phase */
    CRYP_PhaseConfig(CRYP0, CRYP_Final_PH);
    /* Enable Crypto processor */
    CRYP_Cmd(CRYP0, ENABLE);

    /* Wait until the OFNE flag is reset */
    while (CRYP_GetFlagStatus(CRYP0, CRYP_FLAG_OFNE) == RESET) {}

    /* Read the Auth TAG in the IN FIFO */
    temptag[0] = CRYP_DataOut(CRYP0);
    temptag[1] = CRYP_DataOut(CRYP0);
    temptag[2] = CRYP_DataOut(CRYP0);
    temptag[3] = CRYP_DataOut(CRYP0);

    /* Disable Crypto processor */
    CRYP_Cmd(CRYP0, DISABLE);

    /* Copy temporary authentication TAG in user TAG buffer */
    for (loopcounter = 0; loopcounter < tag_len; loopcounter++) {
        /* Set the authentication TAG buffer */
        *((uint8_t*)tagaddr + loopcounter) = *((uint8_t*)temptag + loopcounter);
    }

    if (headersize != 0) {
        mbedtls_free(HBuffer);
    }
    return 0;
}
#endif

#endif /* MBEDTLS_CCM_C */