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
#ifndef MBEDTLS_ACC_CONFIG_H
#define MBEDTLS_ACC_CONFIG_H


/* Enable the Nuclei crypto IP exist macro based on whether SOC have
 * corresponding crypto IP (HASH, CRYP, ACRYP).
 */
#define MBEDTLS_ACC_XLCRYPTO_HASH_ENABLE
#define MBEDTLS_ACC_XLCRYPTO_CRYP_ENABLE
#define MBEDTLS_ACC_XLCRYPTO_ACRYP_ENABLE
/* HASH and CRYP have the option of further acceleration using UDMA while
 * SOC have UDMA IP.
 */
#define MBEDTLS_ACC_XLCRYPTO_UDMA_ENABLE

/* HASH/HMAC */
#if defined(MBEDTLS_ACC_XLCRYPTO_HASH_ENABLE)
/* The enable macros of the HASH algorithm can accelerate hash update phase
 * and finish phase, if you want to speed up you need to enable them both.
 * For example:
 * Turn on MBEDTLS_MD5_UPDATE_ALT and MBEDTLS_MD5_FINISH_ALT to speed up MD5
 * using the HASH accelerator, otherwise not.
 */
/* MD5 update phase(xl-added) */
#define MBEDTLS_MD5_UPDATE_ALT
/* MD5 finish phase(xl-added) */
#define MBEDTLS_MD5_FINISH_ALT
/* SHA1 update phase(xl-added) */
#define MBEDTLS_SHA1_UPDATE_ALT
/* SHA1 finish phase(xl-added) */
#define MBEDTLS_SHA1_FINISH_ALT
/* SHA224/SHA256 update phase(xl-added) */
#define MBEDTLS_SHA256_UPDATE_ALT
/* SHA224/SHA256 finish phase(xl-added) */
#define MBEDTLS_SHA256_FINISH_ALT
/* SHA384/SHA512 update phase(xl-added) */
#define MBEDTLS_SHA512_UPDATE_ALT
/* SHA384/SHA512 finish phase(xl-added) */
#define MBEDTLS_SHA512_FINISH_ALT

/* To use HMAC, turn on all the following enable macros for HMAC based on the
   corresponding hash algorithm */
/* all HMAC algo update key phase(xl-added) */
#define MBEDTLS_MD_UPDATE_ALT
/* all HMAC algo start phase(xl-added) */
#define MBEDTLS_HMAC_START_ALT
/* all HMAC algo update phase(xl-added) */
#define MBEDTLS_HMAC_UPDATE_ALT
/* all HMAC algo finish phase(xl-added) */
#define MBEDTLS_HMAC_FINISH_ALT
/* all HMAC algo reset phase(xl-added) */
#define MBEDTLS_HMAC_RESET_ALT

/* You can choose to use UDMA to accelerate the corresponding HASH algorithm,
   or not */
#if defined(MBEDTLS_ACC_XLCRYPTO_UDMA_ENABLE)
/* HASH/HMAC MD5 DMA(xl-added) */
#define MBEDTLS_MD5_DMA_ALT
/* HASH/HMAC SHA1 DMA(xl-added) */
#define MBEDTLS_SHA1_DMA_ALT
/* HASH/HMAC SHA224/SHA256 DMA(xl-added) */
#define MBEDTLS_SHA256_DMA_ALT
/* HASH/HMAC SHA384/SHA512 DMA(xl-added) */
#define MBEDTLS_SHA512_DMA_ALT
#endif /* MBEDTLS_ACC_XLCRYPTO_UDMA_ENABLE */
#endif /* HASH/HMAC */

/* CRYP */
#if defined(MBEDTLS_ACC_XLCRYPTO_CRYP_ENABLE)
/* DES/3DES supports the ECB/CBC modes. To use DES/3DES algorithm, turn on the following
 * corresponding DES SETKEY enable macros and encryption/decryption enable macros.
 * For example:
 * Turn on MBEDTLS_DES_SET_TRIPLEKEY_EN_ALT, MBEDTLS_DES_SET_TRIPLEKEY_DE_ALT to speed
 * up 3DES set key and MBEDTLS_DES3_CRYPT_ECB_MODE_ALT to speed up 3DES
 * encryption/decryption phase.
 */
/* DES set key base enable macro(mbedtls-existed) */
#define MBEDTLS_DES_SETKEY_ALT
/* DES set encryption key(xl-added) */
#define MBEDTLS_DES_SET_ONEKEY_EN_ALT
/* DES set decryption key(xl-added) */
#define MBEDTLS_DES_SET_ONEKEY_DE_ALT
/* 2DES set encryption key(xl-added) */
#define MBEDTLS_DES_SET_DOUBLEKEY_EN_ALT
/* 2DES set decryption key(xl-added) */
#define MBEDTLS_DES_SET_DOUBLEKEY_DE_ALT
/* 3DES set encryption key(xl-added) */
#define MBEDTLS_DES_SET_TRIPLEKEY_EN_ALT
/* 3DES set decryption key(xl-added) */
#define MBEDTLS_DES_SET_TRIPLEKEY_DE_ALT
/* DES ECB encryption/decryption(xl-added) */
#define MBEDTLS_DES_CRYPT_ECB_MODE_ALT
/* DES CBC encryption/decryption(xl-added) */
#define MBEDTLS_DES_CRYPT_CBC_MODE_ALT
/* 3DES ECB encryption/decryption(xl-added) */
#define MBEDTLS_DES3_CRYPT_ECB_MODE_ALT
/* 3DES CBC encryption/decryption(xl-added) */
#define MBEDTLS_DES3_CRYPT_CBC_MODE_ALT

/* AES supports the ECB/CBC/CTR/GCM/CCM modes. To use AES algorithm, turn on all
 * the following AES SETKEY enable macros and corresponding mode encryption/decryption
 * enable macros.
 * For example:
 * Turn on MBEDTLS_AES_SETKEY_ENC_ALT, MBEDTLS_AES_GCM_SETKEY_ALT and MBEDTLS_AES_GCM_CRYPT_ALT
 * to speed up AES GCM, otherwise not.
 */
/* AES ECB/CBC/CTR/GCM/CCM set encryption key(mbedtls-existed) */
#define MBEDTLS_AES_SETKEY_ENC_ALT
/* AES ECB/CBC set decryption key(mbedtls-existed) */
#define MBEDTLS_AES_SETKEY_DEC_ALT
/* GCM set key(xl-added) */
#define MBEDTLS_AES_GCM_SETKEY_ALT
/* CCM set key(xl-added) */
#define MBEDTLS_AES_CCM_SETKEY_ALT
/* AES ECB encryption(mbedtls-existed) */
#define MBEDTLS_AES_ENCRYPT_ALT
/* AES ECB decryption(mbedtls-existed) */
#define MBEDTLS_AES_DECRYPT_ALT
/* AES ECB multi block encryption/decryption(xl-added) */
#define MBEDTLS_AES_ECB_CRYPT_MULTI_ALT
/* AES CBC encryption/decryption(xl-added) */
#define MBEDTLS_AES_CBC_ALT
/* AES CTR encryption/decryption(xl-added) */
#define MBEDTLS_AES_CTR_ALT
/* GCM encryption/decryption(xl-added) */
#define MBEDTLS_AES_GCM_CRYPT_ALT
/* CCM encryption(xl-added) */
#define MBEDTLS_AES_CCM_ENCRYPT_ALT
/* CCM decryption(xl-added) */
#define MBEDTLS_AES_CCM_DECRYPT_ALT

/* You can choose to use UDMA to accelerate the corresponding CRYP algorithm,
   or not */
#if defined(MBEDTLS_ACC_XLCRYPTO_UDMA_ENABLE)
/* AES ECB/CBC/CTR DMA(xl-added) */
#define MBEDTLS_AES_DMA_ALT
/* DES/3DES DMA(xl-added) */
#define MBEDTLS_DES_DMA_ALT
/* CCM DMA(xl-added) */
#define MBEDTLS_CCM_DMA_ALT
/* GCM DMA(xl-added) */
#define MBEDTLS_GCM_DMA_ALT
#endif /* MBEDTLS_ACC_XLCRYPTO_UDMA_ENABLE */
#endif /* CRYP */

/* ACRYP */
#if defined(MBEDTLS_ACC_XLCRYPTO_ACRYP_ENABLE)
/* BIGNUM supports ACRYP OP_MMAC, OP_MOD, OP_MUL, OP_MEXP and OP_INVMOD acceleration.
 * To use each hardware OP algorithm, turn on the corresponding enable macro.
 */
/* ACRYP OP_MMAC add(xl-added) */
#define MBEDTLS_BIGNUM_ADD_MPI_MPI_ALT
/* ACRYP OP_MMAC sub(xl-added) */
#define MBEDTLS_BIGNUM_SUB_MPI_MPI_ALT
/* ACRYP OP_MOD(xl-added) */
#define MBEDTLS_BIGNUM_MOD_MPI_MPI_ALT
/* ACRYP OP_MUL(xl-added) */
#define MBEDTLS_BIGNUM_MUL_MPI_MPI_ALT
/* ACRYP OP_MEXP(xl-added) */
#define MBEDTLS_BIGNUM_MEXP_MPI_MPI_ALT
/* ACRYP OP_INVMOD(xl-added) */
#define MBEDTLS_BIGNUM_INVMOD_MPI_MPI_ALT
/* In addition to accelerate RSA operation using above BIGNUM enable macro, RSA can
 * also configure the background before the operation using MBEDTLS_RSA_BACKGROUND_ALT,
 * remove the RRmodN operation of OP_MEXP using MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT,
 * and replace the OP_MUL and OP_MUL operation using montmul:MBEDTLS_BIGNUM_MONTMUL_ALT.
 */
/* The RSA_8192 macro needs to be opened when you want to use ACRYP to speed up the RSA8192
 * algorithm. You will not be able to configure the RSA background macros when RSA_8192 is
 * opened due to ACRYP sram memory size limitation.
 */
// #define RSA_8192

#if !defined(RSA_8192)
/* ACRYP RSA modulus N/P/Q background config(xl-added) */
#define MBEDTLS_RSA_BACKGROUND_ALT
/* ACRYP OP_MEXP without RRmodN for RSA(xl-added) */
#define MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT
/* ACRYP OP_MONTMULT for RSA(xl-added) */
#define MBEDTLS_BIGNUM_MONTMUL_ALT
#endif
/* In addition to accelerate ECC operation using above BIGNUM enable macro, ECC can
 * also configure the background of short weierstrass and montgomery curve before the ECC
 * operation, use OP_KMUL and OP_addPoint to accelerate short weierstrass cuve function, and
 * use OP_MMCURVE to accelerate montgomery curve fuction.
 */
/* ACRYP ECC short weierstrass background config(xl-added) */
#define MBEDTLS_ECC_SW_BACKGROUND_ALT
/* ACRYP ECC montgomery background config(xl-added) */
#define MBEDTLS_ECC_MM_BACKGROUND_ALT
/* ACRYP ECC short weierstrass OP_KMUL(xl-added) */
#define MBEDTLS_MUL_SHORT_WEIERSTRASS_ALT
/* ACRYP ECC short weierstrass OP_addPoint(xl-added) */
#define MBEDTLS_ADD_SHORT_WEIERSTRASS_ALT
/* ACRYP ECC montgomery OP_MMCURVE(xl-added) */
#define MBEDTLS_MUL_MONTGOMERY_ALT
#endif /* ACRYP */

/* The following is the ACRYP algorithm length for the OP operation and the parameter offset
 * address configuration macros for the OP operation, which the user should not change.
 */
/* ACRYP OP for BIGNUM algo length */
#define MMAC_LEN            (130)
#define MOD_LEN             (130)
#define MUL_LEN             (130)
#define MEXP_LEN            (130)
#define INVMOD_A_LEN        (130)
#define INVMOD_N_LEN        (130)
#define INVMOD_PARA_LEN     (130)
#define MONTMULT_LEN        (130)

#define RSVD_ADDR_0         (256)
#define VAR_SIZE_MAX        (130)
/* ACRYP MMAC addr */
#define MMAC_OP1_ADDR       (0)
#define MMAC_OP2_ADDR       (MMAC_OP1_ADDR + MMAC_LEN)
#define MMAC_OP3_ADDR       (MMAC_OP2_ADDR + MMAC_LEN)
#define MMAC_RES_ADDR       (MMAC_OP3_ADDR + MMAC_LEN)
/* ACRYP MOD addr */
#define MOD_OP1_ADDR        (0)
#define MOD_OP2_ADDR        (MOD_OP1_ADDR + MOD_LEN)
/* ACRYP MUL addr */
#define MUL_OP1_ADDR        (0)
#define MUL_OP2_ADDR        (MUL_OP1_ADDR + MUL_LEN)
#define MUL_RES_ADDR        (MUL_OP2_ADDR + MUL_LEN)
/* ACRYP MEXP addr */
#define MEXP_A_ADDR         (0)
#define MEXP_E_ADDR         (MEXP_A_ADDR + MEXP_LEN)
#define MEXP_N_ADDR         (MEXP_E_ADDR + MEXP_LEN)
#define MEXP_RR_ADDR        (MEXP_N_ADDR + MEXP_LEN)
#define MEXP_RES_ADDR       (MEXP_RR_ADDR + 2 * MEXP_LEN)
/* ACRYP INVMOD addr */
#define INVMOD_A_ADDR           (0)
#define INVMOD_N_ADDR           (INVMOD_A_ADDR + INVMOD_A_LEN)
#define INVMOD_PARA_ADDR        (RSVD_ADDR_0 + VAR_SIZE_MAX * 5)
#define INVMOD_RST_A_ADDR       (INVMOD_PARA_ADDR + INVMOD_N_LEN)
#define INVMOD_RST_B_ADDR       (INVMOD_RST_A_ADDR + INVMOD_N_LEN)
#define INVMOD_RST_V_ADDR       (INVMOD_RST_B_ADDR + INVMOD_A_LEN)
#define INVMOD_RST_ADD_ADDR     (INVMOD_RST_V_ADDR + INVMOD_N_LEN)
/* ACRYP MONTMULT addr */
#define MONTMULT_A_ADDR         (0)
#define MONTMULT_B_ADDR         (MONTMULT_A_ADDR + MONTMULT_LEN)
#define MONTMULT_N_ADDR         (1600)
#define MONTMULT_N_RR_ADDR      (MONTMULT_N_ADDR + MONTMULT_LEN)
// #define MONTMULT_P_ADDR         (MONTMULT_N_RR_ADDR + 2 * MONTMULT_LEN)
// #define MONTMULT_P_RR_ADDR      (MONTMULT_P_ADDR + MONTMULT_LEN / 2)
// #define MONTMULT_Q_ADDR         (MONTMULT_P_RR_ADDR + MONTMULT_LEN)
// #define MONTMULT_Q_RR_ADDR      (MONTMULT_Q_ADDR + MONTMULT_LEN / 2)

#endif