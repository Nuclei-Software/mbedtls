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

#if defined(MBEDTLS_RSA_C)

#include "acryp_alt.h"
#include "mbedtls/rsa.h"
#include "rsa_alt_helpers.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"

#include <string.h>

#if defined(MBEDTLS_PKCS1_V15) && !defined(__OpenBSD__) && !defined(__NetBSD__)
#include <stdlib.h>
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

extern uint32_t* acryp0_ram;


/*
 * ACRYP mexp/montmult background init (for RSA modulus : N/P/Q)
 */
#if defined(MBEDTLS_RSA_BACKGROUND_ALT)
int mpi_mont_config(const mbedtls_mpi *N, const mbedtls_mpi *P, const mbedtls_mpi *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint32_t N_len_n, N_len_rr;
	mpi mont_n, mont_rr;
    uint8_t field = FIELD_GFP;

    memset((uint8_t *)&acryp0_ram[MONTMULT_N_ADDR], 0, MONTMULT_LEN * 3 * 4);

    /* copy N to ACRYP SRAM */
    N_len_n = N->n;
    memcpy((uint8_t *)&acryp0_ram[MONTMULT_N_ADDR], (uint8_t *)N->p, N_len_n * 4);
    mont_n.n = N_len_n;
    mont_n.p = &acryp0_ram[MONTMULT_N_ADDR];

	/* copy RR to ACRYP SRAM */
    N_len_rr = (N_len_n + 1) * 2 + 1;
    memset((uint8_t *)&acryp0_ram[MONTMULT_N_RR_ADDR], 0, (N_len_rr - 1) * 4);
    acryp0_ram[MONTMULT_N_RR_ADDR + N_len_rr - 1] = 1;
    mont_rr.n = N_len_rr;
    mont_rr.p = &acryp0_ram[MONTMULT_N_RR_ADDR];

    /* modulus N montmult background init */
    montmult_background_init(ACRYP0, field, &mont_n, &mont_rr);

    return ret = 0;
}
#endif

/*
 * ACRYP mexp function without RRmodN (for RSA modulus : N/P/Q)
 */
#if defined(MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT)
int mbedtls_mpi_exp_mod_without_RRmodN( mbedtls_mpi *X, const mbedtls_mpi *A,
                                        const mbedtls_mpi *E, const mbedtls_mpi *N,
                                        uint8_t modulus )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_mpi M;
    uint32_t modulus_addr = 0;
    uint32_t r2_addr = 0;
	uint32_t N_len_a, N_len_e, N_len_n;
	mpi mexp_a, mexp_e;
	uint8_t field = FIELD_GFP;

    /* ACRYP GFP need N odd */
    if( mbedtls_mpi_cmp_int( N, 0 ) <= 0 || ( N->p[0] & 1 ) == 0 )
        return( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    if( mbedtls_mpi_cmp_int( E, 0 ) < 0 )
        return( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    if( mbedtls_mpi_bitlen( E ) > MBEDTLS_MPI_MAX_BITS ||
        mbedtls_mpi_bitlen( N ) > MBEDTLS_MPI_MAX_BITS )
        return ( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    mbedtls_mpi_init( &M );
    mbedtls_mpi_mod_mpi(&M, A ,N);

    if( mbedtls_mpi_cmp_int(&M, 0 ) < 0 )
        return( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    memset((uint8_t *)&acryp0_ram[MEXP_A_ADDR], 0, MEXP_LEN * 6 * 4);

    if (modulus == MONTMULT_N_MODULUS) {
        modulus_addr = MONTMULT_N_ADDR;
        r2_addr = MONTMULT_N_RR_ADDR;
    }
    // else if (modulus == MONTMULT_P_MODULUS) {
    //     modulus_addr = MONTMULT_P_ADDR;
    //     r2_addr = MONTMULT_P_RR_ADDR;
    // } else if (modulus == MONTMULT_Q_MODULUS) {
    //     modulus_addr = MONTMULT_Q_ADDR;
    //     r2_addr = MONTMULT_Q_RR_ADDR;
    // }
    else {
        return( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }

    N_len_a = M.n;
    N_len_e = E->n;
    N_len_n = N->n;

    /* copy to ACRYP SRAM */
    memcpy((uint8_t *)&acryp0_ram[MEXP_A_ADDR], (uint8_t *)M.p, N_len_a * 4);
    memcpy((uint8_t *)&acryp0_ram[MEXP_E_ADDR], (uint8_t *)E->p, N_len_e * 4);

    mexp_a.n = N_len_a;
    mexp_a.p = &acryp0_ram[MEXP_A_ADDR];
    mexp_e.n = N_len_e;
    mexp_e.p = &acryp0_ram[MEXP_E_ADDR];

    /* ACRYP op invN0 */
    background_config_opinvN0(ACRYP0, field, N_len_n);
    op_invn0_func(ACRYP0, modulus_addr);
    /* update modulus and r2 addr to ACRYP */
    rrmodn_addr_config(ACRYP0, MONTMULT_N_ADDR, MONTMULT_N_RR_ADDR);

    /* ACRYP op mexp */
    op_mexp_func(ACRYP0, &mexp_e, &mexp_a, MEXP_RES_ADDR);

    X->s = 1;
    if(mbedtls_mpi_grow(X, N_len_n) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
        return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }
    memcpy((uint8_t *)&X->p[0], (uint8_t *)&acryp0_ram[MEXP_RES_ADDR], N_len_n * 4);

    return ret = 0;
}
#endif

#if defined(MBEDTLS_BIGNUM_MONTMUL_ALT)
/*
 * ACRYP montmult mul: replace mpi mul + mpi mod
 */
int mpi_montmul_alt( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B, const mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t index;
    uint32_t N_len_a, N_len_b, N_len_n;
	uint8_t field = FIELD_GFP;

    for (index = 0; index < (A->n) / 2; index++) {
        if ((A->p[(A->n) / 2 + index]) != 0)
            break;
    }
    if (index == (A->n) / 2) {
        N_len_a = (A->n) / 2;
    } else {
        N_len_a = A->n;
    }

    for (index = 0; index < (B->n) / 2; index++) {
        if ((B->p[(B->n) / 2 + index]) != 0)
            break;
    }
    if (index == (B->n) / 2 ) {
        N_len_b = (B->n) / 2;
    } else {
        N_len_b = B->n;
    }

    N_len_n = N->n;

    memset((uint8_t *)&acryp0_ram[MONTMULT_A_ADDR], 0, MONTMULT_LEN * 2 * 4);

    /* copy to ACRYP SRAM */
    memcpy((uint8_t *)&acryp0_ram[MONTMULT_A_ADDR], (uint8_t *)A->p, N_len_a * 4);
    memcpy((uint8_t *)&acryp0_ram[MONTMULT_B_ADDR], (uint8_t *)B->p, N_len_b * 4);

    /* ACRYP op invN0 */
    background_config_opinvN0(ACRYP0, field, N_len_n);
    op_invn0_func(ACRYP0, MONTMULT_N_ADDR);
    /* update modulus and r2 addr to ACRYP */
    rrmodn_addr_config(ACRYP0, MONTMULT_N_ADDR, MONTMULT_N_RR_ADDR);

    /* ACRYP op montmult */
    op_montmult_func(ACRYP0, MONTMULT_A_ADDR, MONTMULT_N_RR_ADDR, MONTMULT_A_ADDR, MM_MULT);
    op_montmult_func(ACRYP0, MONTMULT_B_ADDR, MONTMULT_N_RR_ADDR, MONTMULT_B_ADDR, MM_MULT);
    op_montmult_func(ACRYP0, MONTMULT_A_ADDR, MONTMULT_B_ADDR, MONTMULT_A_ADDR, MM_MULT);
    op_montmult_func(ACRYP0, MONTMULT_A_ADDR, 0, MONTMULT_A_ADDR, MM_EXIT);

    // short reduction mod
    // mbedtls_mpi_mod_mpi_short_redu(X, &mont_b, &mont_n);

    X->s = A->s * B->s;
    if (mbedtls_mpi_grow(X, N_len_n) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
        return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }
    memcpy((uint8_t *)&X->p[0], (uint8_t *)&acryp0_ram[MONTMULT_A_ADDR], N_len_n * 4);

    return ret = 0;
}

/*
 * ACRYP montmult mul: replace mpi mul + mpi mod
 */
int mpi_montmulself_alt( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t index;
    uint32_t N_len_a, N_len_n;
	uint8_t field = FIELD_GFP;

    for (index = 0; index < (A->n) / 2; index++) {
        if ((A->p[(A->n) / 2 + index]) != 0)
            break;
    }
    if (index == (A->n) / 2) {
        N_len_a = (A->n) / 2;
    } else {
        N_len_a = A->n;
    }

    N_len_n = N->n;

    memset((uint8_t *)&acryp0_ram[MONTMULT_A_ADDR], 0, MONTMULT_LEN * 2 * 4);

    /* copy to ACRYP SRAM */
    memcpy((uint8_t *)&acryp0_ram[MONTMULT_A_ADDR], (uint8_t *)A->p, N_len_a * 4);

    /* ACRYP op invN0 */
    background_config_opinvN0(ACRYP0, field, N_len_n);
    op_invn0_func(ACRYP0, MONTMULT_N_ADDR);
    /* update modulus and r2 addr to ACRYP */
	rrmodn_addr_config(ACRYP0, MONTMULT_N_ADDR, MONTMULT_N_RR_ADDR);

    /* ACRYP op montmult */
    op_montmult_func(ACRYP0, MONTMULT_A_ADDR, MONTMULT_N_RR_ADDR, MONTMULT_A_ADDR, MM_MULT);
    op_montmult_func(ACRYP0, MONTMULT_A_ADDR, MONTMULT_A_ADDR, MONTMULT_A_ADDR, MM_MULT);
    op_montmult_func(ACRYP0, MONTMULT_A_ADDR, 0, MONTMULT_A_ADDR, MM_EXIT);

    //short reduction mod
    // mbedtls_mpi_mod_mpi_short_redu(X, &mont_b, &mont_n);

    X->s = A->s;
    if (mbedtls_mpi_grow(X, N_len_n) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
        return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }
    memcpy((uint8_t *)&X->p[0], (uint8_t *)&acryp0_ram[MONTMULT_A_ADDR], N_len_n * 4);

    return ret = 0;
}
#endif

/*
 * ACRYP get inv mod:a way to replace mbedtls_mpi_inv_mod() for RSA
 */
int mbedtls_rsa_get_inv( mbedtls_rsa_context *ctx, mbedtls_mpi *inv_a, const mbedtls_mpi *a)
{
	int ret = 0;
	mbedtls_mpi p, q, qp, a_p, a_q, inv_a_p ,inv_a_q, h1 ,h2, h, hq;

	mbedtls_mpi_init(&p);
	mbedtls_mpi_init(&q);
	mbedtls_mpi_init(&qp);
	mbedtls_mpi_init(&a_p);
	mbedtls_mpi_init(&a_q);
	mbedtls_mpi_init(&inv_a_p);
	mbedtls_mpi_init(&inv_a_q);
	mbedtls_mpi_init(&h1);
	mbedtls_mpi_init(&h2);
	mbedtls_mpi_init(&h);
	mbedtls_mpi_init(&hq);

	mbedtls_mpi_copy(&p, &ctx->P);
	mbedtls_mpi_copy(&q, &ctx->Q);
	mbedtls_mpi_copy(&qp, &ctx->QP);

    if( a->n >= p.n) {
    	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&a_p, a, &p));
    } else {
    	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&a_p, a));
    }
    if (mbedtls_mpi_cmp_int(&a_p, 0) == 0) {
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }

    if (a->n >= q.n) {
    	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&a_q, a, &q));
    } else {
    	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&a_q, a));
    }
    if (mbedtls_mpi_cmp_int(&a_q, 0) == 0) {
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }

    /* inv_a_p = pow(a_p, -1, p); */
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&inv_a_p, &a_p, &p));
    /* inv_a_q = pow(a_q, -1, q); */
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&inv_a_q, &a_q, &q));

    /* h1 = inv_a_p - inv_a_q; */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&h1, &inv_a_p, &inv_a_q));
    /* h2 = qp * h1; */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h2, &h1, &qp));
    /* h = h2 % p; */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&h, &h2, &p));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&hq, &h, &q));
    /* inv_a = inv_a_q + hq; */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(inv_a, &inv_a_q, &hq));

cleanup:

    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&q);
    mbedtls_mpi_free(&qp);
    mbedtls_mpi_free(&a_p);
    mbedtls_mpi_free(&a_q);
    mbedtls_mpi_free(&inv_a_p);
    mbedtls_mpi_free(&inv_a_q);
    mbedtls_mpi_free(&h1);
    mbedtls_mpi_free(&h2);
    mbedtls_mpi_free(&h);
    mbedtls_mpi_free(&hq);

    return( ret );
}


#if defined(MBEDTLS_SELF_TEST)

#include "mbedtls/sha1.h"

/*
 * Example RSA-8192 keypair, for test purposes
 */
#define KEY_LEN 1024

#define RSA_N   "ceb90313a5c86992c73ca390b3d341e0" \
				"c058a9bf07d83ff85c6fcc5ea384c7dc" \
				"ec2a358846041d402b82527a74c6b203" \
				"3b16f4437fb9f99963d2bb42d5316ecc" \
				"7248f28e8cb02269a0c495162519437b" \
				"e9efe00bd98ed395833a2978c5869c84" \
				"0dacd64cdd53d6ef030bfd148f8a8915" \
				"e9999b2145c7678c3e029ec690c3ff44" \
				"ed3c07319327799e07e9fe166dd463f8" \
				"67f4f657e1111ad7e4c7f3680a421ffb" \
				"f9ee88734fb6dc32346e1e5d55d89180" \
				"9aee1ce3a366999a8213435a96d914cd" \
				"23d2d9840264e3b70cfe778427ee9b35" \
				"4f4fec4bf153712c6394972d716cf0af" \
				"c3a717e1636a657204fd6e960eace32a" \
				"c8823f365d22d34e09d93fa1a15a17bb" \
				"e0e104fb094ed80c56f0c33b69d4371a" \
				"6b316f48c83d88818dac16cc8b5aea93" \
				"834c7ea2200089a0a4a74ef78bd8a03c" \
				"0b8463cbd16910cacec4faa685bb9ea0" \
				"ccb09cac38ad737c9128ceb02497c179" \
				"4cdc30cc19f9c9fb3934c28c2b4faddb" \
				"62d4e8ae5981817b8a9c16304890cf57" \
				"0f5a4e74d753f028c066093c4405d9b0" \
				"f2646949882b7b4086b52d3bffdb26ee" \
				"43de0a7615fdf7b1f84c33a22c1a4fd2" \
				"7914d47af9c1d311221c83ee2a455f34" \
				"1cda47b5c5da5ac2c52656e278f6cdad" \
				"851f5e033354e414467673cab99cc6cd" \
				"f2d6c2a7ccce75a1c016cf19ebed38f5" \
				"6defcd1691578182250d6ea53075010d" \
				"96673b34d4bd7ad38c3657b37a619144" \
				"80671006f4676dcb64f114d8ee6dfb25" \
				"4638261c1fc118708442f28eea48278b" \
				"82370d36b74bd4dab800ee28e051160d" \
				"27a978bd31751a80f265460491433fb4" \
				"cea3a417382dc902f36a9755ab76ad17" \
				"3f0bc269376bd137b9b91b1d545f665b" \
				"5f0aeb4dcfba0e34b963913808082392" \
				"173a577b3768b6ee74c6cceade5d5cf6" \
				"13326ffab676561f5cdcbd56c1494ab4" \
				"7623c56605540d3d242112fe7f21e20a" \
				"c717cadf62991047c77ee53273031518" \
				"0d619584e65beed238a16237db1ea72d" \
				"c0a1ed38552dd62eb06fc6a50cc3f88c" \
				"2d1ecc5bea07730554ae25309d84797e" \
				"4d0bbda84a74259ab084a81b53243549" \
				"ba929c1d57d4d2062c4f1e818374eb8c" \
				"ae7bdce2c36807a059eb29a75aef0645" \
				"5fb2e7c3e81139bfc6b6642b9d05e59d" \
				"82f2843ce3e1feac23a54105722b78c5" \
				"6aaa3bb44298c64550fb528952eee1bd" \
				"e4ff5db70d23635d4d32eae3d30f0e88" \
				"2bad20f837c5569be93c345a6592b3d5" \
				"7f3110e0cc3b45b4a8e993f4a884b183" \
				"af8c8612c1b491ec43d369237992157c" \
				"3169a121b2944efa97fa41ef49d7445e" \
				"3fcc5c09319adba8ae417a7a9066f9ef" \
				"a278f4afa5c8e8554aae1b5c37f58ab8" \
				"cc8a18e62d42d8415261e4eb8ff55a9d" \
				"0fd6289ef8907774755129de21e62425" \
				"8a342b45cab5d59121097e8883e632d4" \
				"f922b627c433e7f642b24c8df7b1d00b" \
				"f95152915f4af4933c4ca9e1f110fd49"

#define RSA_D   "097343c4be2b6f481a7b972ea249e215" \
				"1835f56c9a3b349172085a5b693644bc" \
				"c0bf1d3b6198068e4c6ee4be5c6048fb" \
				"04d483ce2224aa586ccbd16bb8bb4dc9" \
				"62e01ad6916febe2d04aac561ad410d5" \
				"b55815f1f4bc26c80afbb9b19fb60ba9" \
				"adc65cf59e989a96ca98ddb4f6eaea61" \
				"6a106f9b11c98fde45677142ba937b33" \
				"f7746b0fc51e64dce897b5d9e8a370fe" \
				"862218b0e3c518690e3865d437c3d61a" \
				"7ace80c664ba834e783f207c3bd46eb2" \
				"6662c44753ccf8f0ab499e26a206c280" \
				"ae4691530b98f920012410eaa5b8aeb7" \
				"bd2c762cf29751f1298c3d6d02666c8a" \
				"5c73631016af627bd7e68e0ba618193a" \
				"77781cd3ab66502a9d20a55c0a384825" \
				"7a9e4ecffb18f39f7cc9fce2d66fb125" \
				"30094e8111465edb2d52d4a7fd26e6da" \
				"5f823bb7c5a6c0a3eb630aa51e6b84c7" \
				"b9ef0f70dddde3baa1c137842d50ea6b" \
				"876ffb79940db9ddd3f4fd9de7ce5835" \
				"e76199897b1684394be031949ed641a8" \
				"69d839dade94a10ab8c771ec3b250395" \
				"834a299405d3fc82a06909bb0b9108e6" \
				"a1ee1d32135b8982e5a59aafc77e8945" \
				"132d2f653e9421a2ad2b2ea1174b0ca3" \
				"1e8de938c5fa2a5ffa233b94c3b1f02c" \
				"3db56cd9ce75b0f87e72c63e0c319c2d" \
				"768c7c8bc0e8fc9440b4618ebef57fd1" \
				"226cd6f13cd7a361059b0554b6085e36" \
				"3a146057cbc528527ec7226bc2cf5680" \
				"fc83339db2ac06d56cef7f0ae1695c6e" \
				"a43716ef6fa4d0c115930f6e6e00245c" \
				"7779359ceee2bd7b7f7ed5a4aa2341a8" \
				"fea503aece339c0ee7183b0cd0a7396a" \
				"4b24ee1af7a186dd7e26fe6ea2f66408" \
				"1a9342d48fe090369797f559c4036cb7" \
				"bfdceef8f3c8764583438997bb52f753" \
				"b9f8ad2339dcd358d1fb49c8359b8824" \
				"1b958eba852e576d05db8a6e12be2431" \
				"834c2c5a680beaa45cf8ed8876c852c0" \
				"70ea1551c071a85f6a3d84a90971392d" \
				"d6de945f688f60ab56b408863bd59804" \
				"f0ce0b2e95f7268b508f94be7c129b3a" \
				"55cedcad067c31dfe5a634490d05c1bf" \
				"81d5560caee93a18d51b24a694f2c77c" \
				"85038bcf9accc7703a85cc06bf7f6ebb" \
				"ca7e043db81decc0d67762890daf296f" \
				"87d7f85e44de4145b26369068d506a55" \
				"4fabd2d6c76211123f5a5eaccfc01921" \
				"7bf63d1136137241bd8c63a225977130" \
				"e831cd0bec3c19f9e51c025f98601bba" \
				"b68e6ad589e3762d0f2ae7ba3a41452f" \
				"81a3df5c0fc338e32648e13ad8bb0f26" \
				"4ff4a03b7508d4ce6be7fd87bb2313f2" \
				"4b33f83ae23d559503f2d8d23fab081d" \
				"a9900a4457241c6a5d9d9810582adc59" \
				"6eb4b44c863a1f5d5f92cc2d98156a00" \
				"e5d69341d493257637ec1e460e2a54ce" \
				"ceda3ac6a5317c5cf773c744a69ed5f8" \
				"6f21f2d44be309a7ac5116ffad13039c" \
				"cc0e6b7c12f13158f0fefd167ba05906" \
				"b9b348e9959d45d133de96c43c59556c" \
				"ee83a7fe87cc0a38ba4e34c9c00f5341"

#define RSA_E   "10001"

#define RSA_P   "E91E42639F1E0C653EE2FB44337DFB23"  \
				"7C75F41CA43692362E2DA8DAF3657166"  \
				"EB6ADABAF4DE1783EC6F57039E098822"  \
				"4D512C16A98A14E228B518D060D1FCD3"  \
				"E00B92524A62227252EF55FD455E54FE"  \
				"67A3602AD4DC5484072EDB9580E7A68F"  \
				"8874B494C06DFBF01020C67D40CA711F"  \
				"C6D1ABE5BCFE29051B8EE10C2B8F6EAC"  \
				"3CC6A732D3CBD35F83DA2D66C6480AE7"  \
				"2A3E55B057009CB9886D76502C01B370"  \
				"D4357F322AAC8BD64CD4241BC88DCDED"  \
				"940E2342FAF2A177230F334D4CEEB98F"  \
				"83062B525AFFDFED3E08E2604AA9AD6E"  \
				"EF0ECC92655B4E8B81047CFF277318DE"  \
				"009AB16402B5A213FF652B14144D711D"  \
				"ABEC4480A52E6E06EBD6FE2431C11A95"  \
				"CF63D1CA912C766203AB404BDB8C8F8B"  \
				"F828E22C646CB075D56EC5920568BEBD"  \
				"19622EA3225FAC10546D9708A8D7FB3D"  \
				"EBC7DE816DB6677E33127E33984FAEF9"  \
				"5471C995251CC1AF33B71EC12CA4A69D"  \
				"88CD05B9403F21326F85F3247DE36072"  \
				"4AC3F67CB5EF0392A1AFA86C80FCCC83"  \
				"428C0989B7168256847897FCB7DB0618"  \
				"1EF31701D85AFC5666BC5ED07E1C3C5A"  \
				"0238B2096026BE35F86CDA2F48125E39"  \
				"B3FDE1753674DD6FA386E83FFF296121"  \
				"26E6BE88053660EA65DE8E45765094FF"  \
				"4105C5BF7B76C1ED9D66EE5D0A0CFB0C"  \
				"282F86DD0D5A87AEBD8560373C14D189"  \
				"D570BDA8376B60632050DE3C23A0D72D"  \
				"91AD725865B947B8DC8D6FA299A8A66D"

#define RSA_Q   "E3037E208CA28DAB5535A958CB77258D"  \
				"408ED58827D4A93DABAC42E8F5DDF197"  \
				"BEF50354F9EF15A5D2230260C16BF2F5"  \
				"0F0BF94343849D1DD8AF716C1F9B6322"  \
				"ACAED963A1237B925A325F9E01D96478"  \
				"D5A3F45E4718B5F42A1392FD52B97CEA"  \
				"D4806A5764BD71251A6241B7121D6B62"  \
				"9D82CA5698C3069E0B958C07F468DA27"  \
				"04C2A0E9B0397D99422BB463D1EC44DD"  \
				"0C1B97078F460A3A3DF8BF533AAA61F3"  \
				"26CCD3E16EB6C05DB58225B8FC291250"  \
				"57935CABC6B108C98F0020B9F39AF7CA"  \
				"95B00D717FB6FD1565938030239D4DBD"  \
				"93C78CC604AE1B69D4B0AF392F8B0467"  \
				"2D554AE2FD338E6095F2D687CC7EBC60"  \
				"96870180FB7B403707B696960991076B"  \
				"A76CC9F6986201B23B7ED9CF2A068D7A"  \
				"00904D252AB48FC1884C3B359524C44E"  \
				"600474689C8A27C899B7646337EE1540"  \
				"F7FCEAE4CB4FE545A82BDD41541C48BE"  \
				"37975F28AE2D970A448D52B41532BDFB"  \
				"24776EFD6B1C32D11BB7A9D246E19435"  \
				"D2C3E6C61283788A8E06DEE8D2DE720B"  \
				"180B78DFA51662C7DC13A8BA06A5A5B8"  \
				"0240E4AA7F9C7AC2C7A1E34BE4684632"  \
				"767916ECCDCF3C980E56DE7759D8B3C7"  \
				"B7D6EC3ACA80A495E5D7B789E60D30AC"  \
				"2EF2D9C7C59A2CF6369E1B7B8E9450C9"  \
				"766DC888C8B154E91C352489F932FE0C"  \
				"C3D632B8DA4CECA24620D25089331371"  \
				"DED2E6A6A3C7E503705388BCE2498EB8"  \
				"78ADEA4A1508C97F69BFFD12271F98CD"


#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

#if defined(MBEDTLS_PKCS1_V15)
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__) && !defined(__NetBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD && !NetBSD */

    return( 0 );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Checkup routine
 */
int mbedtls_rsa8192_self_test( int verbose )
{
    int ret = 0;
#if defined(MBEDTLS_PKCS1_V15)
    size_t len;
    mbedtls_rsa_context rsa;
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];
#if defined(MBEDTLS_SHA1_C)
    unsigned char sha1sum[20];
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init( &K );
    mbedtls_rsa_init( &rsa );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_N  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, &K, NULL, NULL, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_P  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, &K, NULL, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_Q  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, &K, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_D  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, NULL, &K, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_E  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, NULL, NULL, &K ) );

#if defined(MBEDTLS_RSA_BACKGROUND_ALT)
    /* hardware mexp/montmult background prepare */
    MBEDTLS_MPI_CHK( mpi_mont_config(&rsa.N, &rsa.P, &rsa.Q) );
#endif

    MBEDTLS_MPI_CHK( mbedtls_rsa_complete( &rsa ) );

    if( verbose != 0 )
        mbedtls_printf( "  RSA8192 key validation: " );

    if( mbedtls_rsa_check_pubkey(  &rsa ) != 0 ||
        mbedtls_rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( mbedtls_rsa_pkcs1_encrypt( &rsa, myrand, NULL,
                                   PT_LEN, rsa_plaintext,
                                   rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 decryption : " );

    if( mbedtls_rsa_pkcs1_decrypt( &rsa, myrand, NULL,
                                   &len, rsa_ciphertext, rsa_decrypted,
                                   sizeof(rsa_decrypted) ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

#if defined(MBEDTLS_SHA1_C)
    if( verbose != 0 )
        mbedtls_printf( "  PKCS#1 data sign  : " );

    if( mbedtls_sha1( rsa_plaintext, PT_LEN, sha1sum ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( mbedtls_rsa_pkcs1_sign( &rsa, myrand, NULL,
                                MBEDTLS_MD_SHA1, 20,
                                sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 sig. verify: " );

    if( mbedtls_rsa_pkcs1_verify( &rsa, MBEDTLS_MD_SHA1, 20,
                                  sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );
#endif /* MBEDTLS_SHA1_C */

    if( verbose != 0 )
        mbedtls_printf( "\n" );

cleanup:
    mbedtls_mpi_free( &K );
    mbedtls_rsa_free( &rsa );
#else /* MBEDTLS_PKCS1_V15 */
    ((void) verbose);
#endif /* MBEDTLS_PKCS1_V15 */
    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_RSA_C */