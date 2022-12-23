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

#if defined(MBEDTLS_BIGNUM_C)

// #define MBEDTLS_DEBUG

#include "acryp_alt.h"
#include "mbedtls/bignum.h"
#include "bn_mul.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"

#include <limits.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#define MPI_VALIDATE_RET( cond )                                       \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_MPI_BAD_INPUT_DATA )
#define MPI_VALIDATE( cond )                                           \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#define ciL                 (sizeof(mbedtls_mpi_uint))           /* chars in limb  */
#define biL                 (ciL << 3)                           /* bits  in limb  */
#define biH                 (ciL << 2)                           /* half limb size */

#define MPI_SIZE_T_MAX      ( (size_t) -1 )                      /* SIZE_T_MAX is not standard */

#define MAX_LEN(A, B)       ({uint32_t x = A;uint32_t y = B;x >= y ? x : y;})


extern uint32_t* acryp0_ram;


/*
 * ACRYP Signed addition: X = A + B
 */
#if defined(MBEDTLS_BIGNUM_ADD_MPI_MPI_ALT)
int mbedtls_mpi_add_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t operandFst, operandSec;
    uint32_t N_len_a, N_len_b, N_len_n;
	mac_coefficient_t mac_coe;
	uint8_t field = FIELD_GFP;

    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( B != NULL );

    N_len_a = A->n;
    N_len_b = B->n;
    N_len_n = MAX_LEN(N_len_a, N_len_b);
    if(mbedtls_mpi_grow(X, N_len_n + 1) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
        return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }

    if (BIGNUM_P == A->s) {
        operandFst = MMAC_ADD;
    } else {
        operandFst = MMAC_SUB;
    }
    if (BIGNUM_P == B->s) {
        operandSec = MMAC_ADD;
    } else {
        operandSec = MMAC_SUB;
    }

    /* copy to ACRYP SRAM */
    memset((uint8_t *)&acryp0_ram[MMAC_OP1_ADDR], 0, MMAC_LEN * 4 * 4);
    memcpy((uint8_t *)&acryp0_ram[MMAC_OP2_ADDR], (uint8_t *)A->p, N_len_a * 4);
    memcpy((uint8_t *)&acryp0_ram[MMAC_OP3_ADDR], (uint8_t *)B->p, N_len_b * 4);

    /* 0 (+/-) abs_a (+/-) abs_b */
    op_mmac_config(&mac_coe, THREE_TERMS, operandFst, operandSec);
    background_config_opmmac(ACRYP0, field, N_len_n);
    op_mmac_func(ACRYP0, &mac_coe, MMAC_OP1_ADDR, MMAC_OP2_ADDR, MMAC_OP3_ADDR, MMAC_RES_ADDR);

    /* op mmac result negative */
    if ((acryp0_ram[MMAC_RES_ADDR + N_len_n] & 0x80000000) == 0x80000000) {
        X->s = -1;
        /* transfer to a positive number */
        op_mmac_config(&mac_coe, TWO_TERMS, MMAC_SUB, 0);
        op_mmac_func(ACRYP0, &mac_coe, MMAC_OP1_ADDR, MMAC_RES_ADDR, 0, MMAC_RES_ADDR);
    }
    /* op mmac result positive */
    else {
        X->s = 1;
    }

    /* positive num mpi no overflow*/
    if (acryp0_ram[MMAC_RES_ADDR + N_len_n] == 0) {
        X->n = N_len_n;
    }
    /* positive num mpi overflow */
    else {
        X->n = N_len_n + 1;
    }
    memcpy((uint8_t *)X->p, &acryp0_ram[MMAC_RES_ADDR], X->n * 4);

    return ret = 0;
}
#endif

/*
 * ACRYP Signed subtraction: X = A - B
 */
#if defined(MBEDTLS_BIGNUM_SUB_MPI_MPI_ALT)
int mbedtls_mpi_sub_mpi( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t operandFst, operandSec;
    uint32_t N_len_a, N_len_b, N_len_n;
	mac_coefficient_t mac_coe;
	uint8_t field = FIELD_GFP;

    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( B != NULL );

    N_len_a = A->n;
    N_len_b = B->n;
    N_len_n = MAX_LEN(N_len_a, N_len_b);
    if (mbedtls_mpi_grow(X, N_len_n + 1) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
        return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }

    if (BIGNUM_P == A->s) {
        operandFst = MMAC_ADD;
    } else {
        operandFst = MMAC_SUB;
    }
    if (BIGNUM_P == B->s) {
        operandSec = MMAC_SUB;
    } else {
        operandSec = MMAC_ADD;
    }

    /* copy to ACRYP SRAM */
    memset((uint8_t *)&acryp0_ram[MMAC_OP1_ADDR], 0, MMAC_LEN * 4 * 4);
    memcpy((uint8_t *)&acryp0_ram[MMAC_OP2_ADDR], (uint8_t *)A->p, N_len_a * 4);
    memcpy((uint8_t *)&acryp0_ram[MMAC_OP3_ADDR], (uint8_t *)B->p, N_len_b * 4);

    /* 0 (+/-) abs_a (+/-) abs_b */
    op_mmac_config(&mac_coe, THREE_TERMS, operandFst, operandSec);
    background_config_opmmac(ACRYP0, field, N_len_n);
    op_mmac_func(ACRYP0, &mac_coe, MMAC_OP1_ADDR, MMAC_OP2_ADDR, MMAC_OP3_ADDR, MMAC_RES_ADDR);

    /* op mmac result negative */
    if ((acryp0_ram[MMAC_RES_ADDR + N_len_n] & 0x80000000) == 0x80000000) {
        X->s = -1;
        /* transfer to a positive number */
        op_mmac_config(&mac_coe, TWO_TERMS, MMAC_SUB, 0);
        op_mmac_func(ACRYP0, &mac_coe, MMAC_OP1_ADDR, MMAC_RES_ADDR, 0, MMAC_RES_ADDR);
    }
    /* op mmac result positive */
    else {
        X->s = 1;
    }

    /* positive num mpi no overflow*/
    if (acryp0_ram[MMAC_RES_ADDR + N_len_n] == 0) {
        X->n = N_len_n;
    }
    /* positive num mpi overflow */
    else {
        X->n = N_len_n + 1;
    }
    memcpy((uint8_t *)X->p, &acryp0_ram[MMAC_RES_ADDR], X->n * 4);

    return ret = 0;
}
#endif

/*
 * ACRYP Modulo: R = A mod B
 */
#if defined(MBEDTLS_BIGNUM_MOD_MPI_MPI_ALT)
int mbedtls_mpi_mod_mpi( mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint32_t N_len_a, N_len_b;
	mbedtls_mpi_uint *a, *b;
	uint32_t i = 0;
    uint32_t carry = 0;
    uint32_t carry_next = 0;
	uint8_t field = FIELD_GFP;

    MPI_VALIDATE_RET( R != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( B != NULL );

    if( mbedtls_mpi_cmp_int( B, 0 ) < 0 )
        return( ret = MBEDTLS_ERR_MPI_NEGATIVE_VALUE );

    memset((uint8_t *)&acryp0_ram[MOD_OP1_ADDR], 0, MOD_LEN * 2 * 4);

    N_len_a = A->n;
    N_len_b = B->n;

    if (N_len_a < N_len_b) {
        if (A->s == 1) {
            mbedtls_mpi_copy(R, A);
        } else {
            mbedtls_mpi_add_mpi(R, A, B);
        }
        return ret = 0;
    }

    if( ( a = (mbedtls_mpi_uint*)mbedtls_calloc(( N_len_a + 1), ciL ) ) == NULL ) {
        return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }

    if( ( b = (mbedtls_mpi_uint*)mbedtls_calloc(( N_len_b + 1), ciL ) ) == NULL ) {
        return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }

    memcpy((uint8_t *)a, (uint8_t *)A->p, N_len_a * 4);
    memcpy((uint8_t *)b, (uint8_t *)B->p, N_len_b * 4);

    /* transfer input mpi negative to ACRYP storage format */
    if (A->s == -1) {
        carry = 1;
        carry_next = 0;
        for(i = 0;i < N_len_a + 1;i++) {
            if ((!a[i]) && carry) {
                carry_next = 1;
            } else {
                carry_next = 0;
            }
            a[i] = ~a[i] + carry;
            carry = carry_next;
        }
    }

    /* copy to ACRYP SRAM */
    memcpy((uint8_t *)&acryp0_ram[MOD_OP1_ADDR], (uint8_t *)&a[0], (N_len_a + 1) * 4);
    memcpy((uint8_t *)&acryp0_ram[MOD_OP2_ADDR], (uint8_t *)&b[0], (N_len_b + 1) * 4);
    mbedtls_free(a);
    mbedtls_free(b);

    /* ACRYP op mod */
    background_config_opmod(ACRYP0, field, N_len_a, N_len_b);
    op_mod_func(ACRYP0, MOD_OP1_ADDR, MOD_OP2_ADDR, MOD_NORMAL);

    /* mod result no negative*/
    R->s = 1;

    if (R->n >= N_len_b) {
        R->n = N_len_b;
    } else {
        if(mbedtls_mpi_grow(R, N_len_b) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
            return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
        }
    }
    memcpy((uint8_t *)&R->p[0], (uint8_t *)&acryp0_ram[MOD_OP1_ADDR], N_len_b * 4);

    return ret = 0;
}
#endif

/*
 * ACRYP Baseline multiplication: X = A * B  (HAC 14.12)
 */
#if defined(MBEDTLS_BIGNUM_MUL_MPI_MPI_ALT)
int mbedtls_mpi_mul_mpi( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, j;
	int result_is_zero = 0;
	uint32_t N_len_a, N_len_b;
	uint8_t field = FIELD_GFP;
    int index;
    uint32_t N_len_max, N_len_last, N_len_rst;

    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( B != NULL );

    memset((uint8_t *)&acryp0_ram[MUL_OP1_ADDR], 0, MUL_LEN * 4 * 4);

    for( i = A->n; i > 0; i-- )
        if( A->p[i - 1] != 0 )
            break;
    if( i == 0 )
        result_is_zero = 1;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;
    if( j == 0 )
        result_is_zero = 1;

    N_len_a = A->n;
    N_len_b = B->n;

    /* copy to ACRYP SRAM */
    memcpy((uint8_t *)&acryp0_ram[MUL_OP1_ADDR], (uint8_t *)A->p, N_len_a * 4);
    memcpy((uint8_t *)&acryp0_ram[MUL_OP2_ADDR], (uint8_t *)B->p, N_len_b * 4);

    /* ACRYP op mul */
    background_config_opmul(ACRYP0, field, N_len_a, N_len_b);
    op_mul_func(ACRYP0, MUL_OP1_ADDR, MUL_OP2_ADDR, MUL_RES_ADDR);

    if ( result_is_zero ) {
        X->s = 1;
    } else {
        X->s = A->s * B->s;
    }

    /* remove extra mpi zeros from the correct result */
    N_len_max = MAX_LEN(N_len_a, N_len_b);
    N_len_last = N_len_a + N_len_b - N_len_max;
    for (index = N_len_last; index >= 0; index--) {
        if ((acryp0_ram[MUL_RES_ADDR + N_len_max + index]) != 0)
            break;
    }
    N_len_rst = N_len_max + index + 1;

    if (X->n >= N_len_rst) {
        X->n = N_len_rst;
    } else {
        if(mbedtls_mpi_grow(X, N_len_rst) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
            return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
        }
    }
    memcpy((uint8_t *)&X->p[0], (uint8_t *)&acryp0_ram[MUL_RES_ADDR], N_len_rst * 4);

    return ret = 0;
}
#endif

/*
 * ACRYP Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
#if defined(MBEDTLS_BIGNUM_INVMOD_MPI_MPI_ALT)
int mbedtls_mpi_inv_mod( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t N_len_a, N_len_n, temp_len;
	uint8_t field = FIELD_GFP;
	uint32_t Addr_s = INVMOD_RST_ADD_ADDR;

    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( N != NULL );

    if( mbedtls_mpi_cmp_int( N, 1 ) <= 0 )
        return( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    if( mbedtls_mpi_cmp_int( A, 0 ) <= 0 ) {
        return( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }

    N_len_a = A->n;
    N_len_n = N->n;
    uint32_t N_len_inv = MAX_LEN(N_len_a, N_len_n);

    if (N_len_inv > 129) {
       return( ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }

    memset((uint8_t *)&acryp0_ram[INVMOD_A_ADDR], 0, 1600 * 4);

    /* copy to ACRYP SRAM */
    memcpy((uint8_t *)&acryp0_ram[INVMOD_A_ADDR], (uint8_t *)A->p, (N_len_a) * 4);
    memcpy((uint8_t *)&acryp0_ram[INVMOD_N_ADDR], (uint8_t *)N->p, (N_len_n) * 4);
    acryp0_ram[INVMOD_PARA_ADDR] = 0x1;

    /* ACRYP op inv */
    background_config_opinv(ACRYP0, field, N_len_inv);
    op_inv_func(ACRYP0, INVMOD_A_ADDR, INVMOD_N_ADDR, INVMOD_PARA_ADDR, INVMOD_RST_V_ADDR, INVMOD_RST_A_ADDR, INVMOD_RST_B_ADDR);

    /* transfer inv result negative to positive in ACRYP sram */
    if ((acryp0_ram[INVMOD_RST_A_ADDR + N_len_n ] & 0x80000000) == 0x80000000) {
        mac_coefficient_t mac_coe;
        op_mmac_config(&mac_coe, TWO_TERMS, MMAC_ADD, 0);
        background_config_opmmac(ACRYP0, field, N_len_n);
        op_mmac_func(ACRYP0, &mac_coe, INVMOD_RST_A_ADDR, INVMOD_N_ADDR, 0, Addr_s);
    } else {
        memcpy((uint8_t *)&acryp0_ram[Addr_s], (uint8_t *)&acryp0_ram[INVMOD_RST_A_ADDR], N_len_n * 4);
    }

    X->s = 1;
    if (X->n > N_len_n) {
        temp_len = X->n;
        X->n = N_len_n;
        /* grow length to actual useful*/
        if (mbedtls_mpi_grow(X, N_len_n) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
            return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
        }
        // /* same as input length */
        if (mbedtls_mpi_grow(X, temp_len) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
            return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
        }
    } else {
        if (mbedtls_mpi_grow(X, N_len_n) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
            return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
        }
    }
    memcpy((uint8_t *)&X->p[0], (uint8_t *)&acryp0_ram[Addr_s], N_len_n * 4);

    return ret = 0;
}
#endif

/*
 * ACRYP Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */
#if defined(MBEDTLS_BIGNUM_MEXP_MPI_MPI_ALT)
int mbedtls_mpi_exp_mod( mbedtls_mpi *X, const mbedtls_mpi *A,
                         const mbedtls_mpi *E, const mbedtls_mpi *N,
                         mbedtls_mpi *prec_RR )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_mpi M;
	uint32_t N_len_a, N_len_e, N_len_n;
	mpi mexp_a, mexp_e, mexp_n, mexp_rr;
	uint8_t field = FIELD_GFP;

    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( E != NULL );
    MPI_VALIDATE_RET( N != NULL );

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

    N_len_a = M.n;
    N_len_e = E->n;
    N_len_n = N->n;

    /* copy to ACRYP SRAM */
    memcpy((uint8_t *)&acryp0_ram[MEXP_A_ADDR], (uint8_t *)M.p,  N_len_a * 4);
    memcpy((uint8_t *)&acryp0_ram[MEXP_E_ADDR], (uint8_t *)E->p, N_len_e * 4);
    memcpy((uint8_t *)&acryp0_ram[MEXP_N_ADDR], (uint8_t *)N->p, N_len_n * 4);

    mexp_a.n = N_len_a;
    mexp_a.p = &acryp0_ram[MEXP_A_ADDR];
    mexp_e.n = N_len_e;
    mexp_e.p = &acryp0_ram[MEXP_E_ADDR];
    mexp_n.n = N_len_n;
    mexp_n.p = &acryp0_ram[MEXP_N_ADDR];

    mexp_rr.n = ((N_len_n + 1) * 2 + 1);
    memset(&acryp0_ram[MEXP_RR_ADDR], 0, (mexp_rr.n - 1) * 4);
    acryp0_ram[MEXP_RR_ADDR + mexp_rr.n - 1] = 0x1;
    mexp_rr.p = &acryp0_ram[MEXP_RR_ADDR];

    /* ACRYP op montmult */
    montmult_background_init(ACRYP0, field, &mexp_n, &mexp_rr);
    /* ACRYP op mexp */
    op_mexp_func(ACRYP0, &mexp_e, &mexp_a, MEXP_RES_ADDR);

    X->s = 1;
    if (X->n >= N_len_n) {
       X->n = N_len_n;
    } else {
        if(mbedtls_mpi_grow(X, N_len_n) == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
            return( ret = MBEDTLS_ERR_MPI_ALLOC_FAILED );
        }
    }
    memcpy((uint8_t *)&X->p[0], (uint8_t *)&acryp0_ram[MEXP_RES_ADDR], N_len_n * 4);

    return ret = 0;
}
#endif


#if defined(MBEDTLS_SELF_TEST)
/*
 * Checkup ACRYP Bignum add/sub/mod
 */
static int mbedtls_mpi_self_test_add_sub_mod( int verbose )
{
    int ret = 0;
    mbedtls_mpi_sint c = -1;
    mbedtls_mpi A, E, X, U;

    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &U ); mbedtls_mpi_init( &X );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &A, 16, "22222222222222222222222222222222" ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &E, 16, "33333333333333333333333333333333" ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16, "55555555555555555555555555555555" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi(&X, &A, &E) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #1 (add_mpi): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16, "22222222222222222222222222222221" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int(&X, &A, c) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #2 (add_int): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16, "11111111111111111111111111111111" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi(&X, &E, &A) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #3 (sub_mpi): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16, "22222222222222222222222222222223" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int(&X, &A, c) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #4 (sub_int): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16, "11111111111111111111111111111111" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi(&X, &E, &A) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #5 (mod_mpi): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

cleanup:

    if( ret != 0 && verbose != 0 )
        mbedtls_printf( "Unexpected error, return code = %08X\n", (unsigned int) ret );

    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &U ); mbedtls_mpi_free( &X );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( ret );
}

/*
 * Checkup ACRYP Bignum mul/exp/inv
 */
static int mbedtls_mpi_self_test_mul_exp_inv( int verbose )
{
    int ret = 0;
    int i = 0;
    mbedtls_mpi A, E, N, X, Y, U, V;

    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &N ); mbedtls_mpi_init( &X );
    mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &U ); mbedtls_mpi_init( &V );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &A, 16,
        "EFE021C2645FD1DC586E69184AF4A31E" \
        "D5F53E93B5F123FA41680867BA110131" \
        "944FE7952E2517337780CB0DB80E61AA" \
        "E7C8DDC6C5C6AADEB34EB38A2F40D5E6" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &E, 16,
        "B2E7EFD37075B9F03FF989C7C5051C20" \
        "34D2A323810251127E7BF8625A4F49A5" \
        "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
        "5B5C25763222FEFCCFC38B832366C29E" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &N, 16,
        "0066A198186C18C10B2F5ED9B522752A" \
        "9830B69916E535C8F047518A889A43A5" \
        "94B6BED27A168D31D4A52F88925AA8F5" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &X, &A, &N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "602AB7ECA597A3D6B56FF9829A5E8B85" \
        "9E857EA95A03512E2BAE7391688D264A" \
        "A5663B0341DB9CCFD2C4C5F421FEC814" \
        "8001B72E848A38CAE1C65F78E56ABDEF" \
        "E12D3C039B8A02D6BE593F0BBBDA56F1" \
        "ECF677152EF804370C1A305CAF3B5BF1" \
        "30879B56C61DE584A0F53A2447A51E" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #6 (mul_mpi): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &X, &A, &E, &N, NULL ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "36E139AEA55215609D2816998ED020BB" \
        "BD96C37890F65171D948E9BC7CBAA4D9" \
        "325D24D6A3C12710F10A09FA08AB87" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #7 (exp_mod): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &X, &A, &N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "003A0AAEDD7E784FC07D8F9EC6E3BFD5" \
        "C3DBA76456363A10869622EAC2DD84EC" \
        "C5B8A74DAC4D09E03B5E0BE779F2DF61" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #8 (inv_mod): " );

    if( mbedtls_mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

cleanup:

    if( ret != 0 && verbose != 0 )
        mbedtls_printf( "Unexpected error, return code = %08X\n", (unsigned int) ret );

    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &N ); mbedtls_mpi_free( &X );
    mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &U ); mbedtls_mpi_free( &V );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( ret );
}

int mbedtls_mpi_self_test_alt( int verbose )
{
    int ret = 0;
    ret = mbedtls_mpi_self_test_add_sub_mod(verbose);
    if( ret != 0)
        return ret;
    ret = mbedtls_mpi_self_test_mul_exp_inv(verbose);
    if( ret != 0)
        return ret;
    return 0;
}
#endif

#endif /* MBEDTLS_BIGNUM_C */