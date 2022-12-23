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

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
#endif

#if defined(MBEDTLS_ECP_C)

#include "acryp_alt.h"
#include "mbedtls/ecp.h"
#include "mbedtls/threading.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "bn_mul.h"
#include "ecp_invasive.h"

#include <string.h>

#if !defined(MBEDTLS_ECP_ALT)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "ecp_internal_alt.h"

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

extern uint32_t* acryp0_ram;

/* ACRYP OP for ECC algo length */
#define ECP_LEN                 (35)
/* ACRYP ECC Kmul/add_point data addr */
#define ECP_QX_ADDR             (0)
#define ECP_QY_ADDR             (ECP_QX_ADDR + ECP_LEN)
#define ECP_QZ_ADDR             (ECP_QY_ADDR + ECP_LEN)
#define ECP_KEY_ADDR            (ECP_QZ_ADDR + ECP_LEN)
#define ECP_PX_ADDR             (ECP_KEY_ADDR + ECP_LEN)
#define ECP_PY_ADDR             (ECP_PX_ADDR + ECP_LEN)
/* ACRYP ECC background addr */
#define ECP_N_ADDR              (1600)
#define ECP_RR_ADDR             (ECP_N_ADDR + ECP_LEN)
#define ECP_A_ADDR              (ECP_RR_ADDR + 2 * ECP_LEN)
#define ECP_B_ADDR              (ECP_A_ADDR + ECP_LEN)
#define ECP_N_M2_ADDR           (ECP_B_ADDR + ECP_LEN)


/* Needs f_rng, p_rng to be defined. */
#define MPI_ECP_RAND( X )                                                       \
    MBEDTLS_MPI_CHK( mbedtls_mpi_random( (X), 2, &grp->P, f_rng, p_rng ) )

#define MPI_ECP_VALID( X )                      \
    ( (X)->p != NULL )

#define MPI_ECP_CMP( X, Y )                                                     \
    mbedtls_mpi_cmp_mpi( X, Y )

#define MPI_ECP_CMP_INT( X, c )                                                 \
    mbedtls_mpi_cmp_int( X, c )


#if defined(MBEDTLS_ECC_SW_BACKGROUND_ALT)
/*
 * ACRYP ECC short weierstarss standard NIST curve background init (GFP)
 */
int ecp_sw_nist_curve_init(const mbedtls_mpi *N, const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t N_len_n, N_len_rr;
    mbedtls_mpi mpi_a, mpi_n_m2;
    mpi mpi_ecp_n, mpi_ecp_rr, mpi_ecp_a, mpi_ecp_b, mpi_ecp_n_m2;
    uint8_t field = FIELD_GFP;

    mbedtls_mpi_init(&mpi_a);
    mbedtls_mpi_init(&mpi_n_m2);

    /* calc ACRYP ECC curve para a/n_m2 */
    mbedtls_mpi_sub_int(&mpi_a, N, 3);
    mbedtls_mpi_sub_int(&mpi_n_m2, N, 2);

    /* empty the ECC short weierstarss background space */
    memset((uint8_t *)&acryp0_ram[ECP_N_ADDR], 0, ECP_LEN * 6 * 4);

    N_len_n = N->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_N_ADDR], (uint8_t *)N->p, N_len_n * 4);
    mpi_ecp_n.n = N_len_n;
    mpi_ecp_n.p = &acryp0_ram[ECP_N_ADDR];

    N_len_rr = (N_len_n + 1) * 2 + 1;
    memset((uint8_t *)&acryp0_ram[ECP_RR_ADDR], 0, (N_len_rr - 1) * 4);
    acryp0_ram[ECP_RR_ADDR + N_len_rr - 1] = 1;
    mpi_ecp_rr.n = N_len_rr;
    mpi_ecp_rr.p = &acryp0_ram[ECP_RR_ADDR];

    mpi_ecp_a.n = mpi_a.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_A_ADDR], (uint8_t *)mpi_a.p, mpi_a.n * 4);
    mpi_ecp_a.p = &acryp0_ram[ECP_A_ADDR];

    mpi_ecp_b.n = B->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_B_ADDR], (uint8_t *)B->p, B->n * 4);
    mpi_ecp_b.p = &acryp0_ram[ECP_B_ADDR];

    mpi_ecp_n_m2.n = mpi_n_m2.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_N_M2_ADDR], (uint8_t *)mpi_n_m2.p, mpi_n_m2.n * 4);
    mpi_ecp_n_m2.p = &acryp0_ram[ECP_N_M2_ADDR];

    /* short weierstrass curve background init */
    ecc_sw_background_init(ACRYP0, field, &mpi_ecp_n, &mpi_ecp_rr, &mpi_ecp_a, &mpi_ecp_b, &mpi_ecp_n_m2);

    return 0;
}

/*
 * ACRYP ECC short weierstarss standard SECG/BrainPool curve background init (GFP)
 */
int ecp_sw_secg_brainpool_curve_init(const mbedtls_mpi *N, const mbedtls_mpi *A, const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t N_len_n, N_len_rr;
    mbedtls_mpi mpi_n_m2;
    mpi mpi_ecp_n, mpi_ecp_rr, mpi_ecp_a, mpi_ecp_b, mpi_ecp_n_m2;
    uint8_t field = FIELD_GFP;

    mbedtls_mpi_init(&mpi_n_m2);

    /* calc ACRYP ECC curve para n_m2 */
    mbedtls_mpi_sub_int(&mpi_n_m2, N, 2);

    /* empty the ECC short weierstarss background space */
    memset((uint8_t *)&acryp0_ram[ECP_N_ADDR], 0, ECP_LEN * 6 * 4);

    N_len_n = N->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_N_ADDR], (uint8_t *)N->p, N_len_n * 4);
    mpi_ecp_n.n = N_len_n;
    mpi_ecp_n.p = &acryp0_ram[ECP_N_ADDR];

    N_len_rr = (N_len_n + 1) * 2 + 1;
    memset((uint8_t *)&acryp0_ram[ECP_RR_ADDR], 0, (N_len_rr - 1) * 4);
    acryp0_ram[ECP_RR_ADDR + N_len_rr - 1] = 1;
    mpi_ecp_rr.n = N_len_rr;
    mpi_ecp_rr.p = &acryp0_ram[ECP_RR_ADDR];

    mpi_ecp_a.n = A->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_A_ADDR], (uint8_t *)A->p, A->n * 4);
    mpi_ecp_a.p = &acryp0_ram[ECP_A_ADDR];

    mpi_ecp_b.n = B->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_B_ADDR], (uint8_t *)B->p, B->n * 4);
    mpi_ecp_b.p = &acryp0_ram[ECP_B_ADDR];

    mpi_ecp_n_m2.n = mpi_n_m2.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_N_M2_ADDR], (uint8_t *)mpi_n_m2.p, mpi_n_m2.n * 4);
    mpi_ecp_n_m2.p = &acryp0_ram[ECP_N_M2_ADDR];

    /* short weierstrass curve background init */
    ecc_sw_background_init(ACRYP0, field, &mpi_ecp_n, &mpi_ecp_rr, &mpi_ecp_a, &mpi_ecp_b, &mpi_ecp_n_m2);

    return 0;
}
#endif

/*
 * ACRYP ECC montgomery curve background init (GFP)
 */
#if defined(MBEDTLS_ECC_MM_BACKGROUND_ALT)
int ecp_montgomery_curve_init(const mbedtls_mpi *N, const mbedtls_mpi *D)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t N_len_n, N_len_rr;
    mbedtls_mpi mpi_d, mpi_n_m2;
    mpi mpi_ecp_n, mpi_ecp_rr, mpi_ecp_d, mpi_ecp_n_m2;
    uint8_t field = FIELD_GFP;

    mbedtls_mpi_init(&mpi_n_m2);
    mbedtls_mpi_init(&mpi_d);

    /* calc ACRYP ECC curve para d/n_m2 */
    mbedtls_mpi_sub_int(&mpi_n_m2, N, 2);
    mbedtls_mpi_sub_int(&mpi_d, D, 1);

    /* empty the ECC montgomery background space */
    memset((uint8_t *)&acryp0_ram[ECP_N_ADDR], 0, ECP_LEN * 6 * 4);

    N_len_n = N->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_N_ADDR], (uint8_t *)N->p, N_len_n * 4);
    mpi_ecp_n.n = N_len_n;
    mpi_ecp_n.p = &acryp0_ram[ECP_N_ADDR];

    N_len_rr = (N_len_n + 1) * 2 + 1;
    memset((uint8_t *)&acryp0_ram[ECP_RR_ADDR], 0, (N_len_rr - 1) * 4);
    acryp0_ram[ECP_RR_ADDR + N_len_rr - 1] = 1;
    mpi_ecp_rr.n = N_len_rr;
    mpi_ecp_rr.p = &acryp0_ram[ECP_RR_ADDR];

    mpi_ecp_d.n = mpi_d.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_A_ADDR], (uint8_t *)mpi_d.p, mpi_d.n * 4);
    mpi_ecp_d.p = &acryp0_ram[ECP_A_ADDR];

    mpi_ecp_n_m2.n = mpi_n_m2.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_N_M2_ADDR], (uint8_t *)mpi_n_m2.p, mpi_n_m2.n * 4);
    mpi_ecp_n_m2.p = &acryp0_ram[ECP_N_M2_ADDR];

    /* montgomery/edwards curve background init */
    ecc_ed_mm_background_init(ACRYP0, field, &mpi_ecp_n, &mpi_ecp_rr, &mpi_ecp_d, &mpi_ecp_n_m2);

    return 0;
}
#endif

/*
 * Multiplication - for curves in short Weierstrass form
 */
#if defined(MBEDTLS_MUL_SHORT_WEIERSTRASS_ALT)
int ecp_mul_comb( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                  const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng,
                  mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l;
    uint32_t N_len_n = 0;
    mpi mpi_ecp_qx, mpi_ecp_qy, mpi_ecp_qz, mpi_ecp_key;
    uint8_t field = FIELD_GFP;

    mbedtls_mpi_init( &l );

    if( f_rng != 0 ) {
        MPI_ECP_RAND( &l );
        MPI_ECP_RAND( &l );
    }

    /* empty the ECC short weierstarss data space */
    memset((uint8_t *)&acryp0_ram[ECP_QX_ADDR], 0, ECP_LEN * 6 * 4);

    N_len_n = grp->P.n;

    /* short weierstrass curve background addr config */
    ecc_sw_background_config(ACRYP0, field, N_len_n, ECP_N_ADDR, ECP_RR_ADDR, ECP_A_ADDR, ECP_B_ADDR, ECP_N_M2_ADDR);

    /*Qx/Qy/Qz/KEY Init*/
    mpi_ecp_qx.n = P->X.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QX_ADDR], (uint8_t *)P->X.p, P->X.n * 4);
    mpi_ecp_qx.p = &acryp0_ram[ECP_QX_ADDR];

    mpi_ecp_qy.n = P->Y.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QY_ADDR], (uint8_t *)P->Y.p, P->Y.n * 4);
    mpi_ecp_qy.p = &acryp0_ram[ECP_QY_ADDR];

    mpi_ecp_qz.n = P->Z.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QZ_ADDR], (uint8_t *)P->Z.p, P->Z.n * 4);
    mpi_ecp_qz.p = &acryp0_ram[ECP_QZ_ADDR];

    mpi_ecp_key.n = m->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_KEY_ADDR], (uint8_t *)m->p, m->n * 4);
    mpi_ecp_key.p = &acryp0_ram[ECP_KEY_ADDR];

    /* short weierstrass curve mul to affine */
    op_kmul_func(ACRYP0, &mpi_ecp_qx, &mpi_ecp_qy, &mpi_ecp_qz, &mpi_ecp_key, C_AFF);

    mbedtls_mpi_grow(&R->X, 2 * N_len_n);
    mbedtls_mpi_grow(&R->Y, 2 * N_len_n);
    mbedtls_mpi_grow(&R->Z, 2 * N_len_n);

    memcpy((uint8_t *)&R->X.p[0], (uint8_t *)&acryp0_ram[ECP_QX_ADDR], 2 * N_len_n * 4);
    memcpy((uint8_t *)&R->Y.p[0], (uint8_t *)&acryp0_ram[ECP_QY_ADDR], 2 * N_len_n * 4);
    R->Z.p[0] = 0x1;

cleanup:
    mbedtls_mpi_free( &l );
    return 0;
}
#endif

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates
 */
#if defined(MBEDTLS_ADD_SHORT_WEIERSTRASS_ALT)
int ecp_add_mixed( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                   const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q,
                   mbedtls_mpi tmp[4] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t N_len_n = 0;
    mpi mpi_ecp_qx, mpi_ecp_qy, mpi_ecp_qz, mpi_ecp_px, mpi_ecp_py;
    uint8_t field = FIELD_GFP;

    if( !MPI_ECP_VALID( &Q->Z ) )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if( MPI_ECP_CMP_INT( &P->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, Q ) );

    if( MPI_ECP_CMP_INT( &Q->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, P ) );

    /*
     * Make sure Q coordinates are normalized
     */
    if( MPI_ECP_CMP_INT( &Q->Z, 1 ) != 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /* empty the ECC short weierstarss data space */
    memset((uint8_t *)&acryp0_ram[ECP_QX_ADDR], 0, ECP_LEN * 6 * 4);

    N_len_n = grp->P.n;

    /* short weierstrass curve background addr config */
    ecc_sw_background_config(ACRYP0, field, N_len_n, ECP_N_ADDR, ECP_RR_ADDR, ECP_A_ADDR, ECP_B_ADDR, ECP_N_M2_ADDR);

    /*Qx/QY/QZ Jacobian Init*/
    mpi_ecp_qx.n = Q->X.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QX_ADDR], (uint8_t *)Q->X.p, Q->X.n * 4);
    mpi_ecp_qx.p = &acryp0_ram[ECP_QX_ADDR];

    mpi_ecp_qy.n = Q->Y.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QY_ADDR], (uint8_t *)Q->Y.p, Q->Y.n * 4);
    mpi_ecp_qy.p = &acryp0_ram[ECP_QY_ADDR];

    mpi_ecp_qz.n = Q->Z.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QZ_ADDR], (uint8_t *)Q->Z.p, Q->Z.n * 4);
    mpi_ecp_qz.p = &acryp0_ram[ECP_QZ_ADDR];

    /*Px/Py affine Init*/
    mpi_ecp_px.n = P->X.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_PX_ADDR], (uint8_t *)P->X.p, P->X.n * 4);
    mpi_ecp_px.p = &acryp0_ram[ECP_PX_ADDR];

    mpi_ecp_py.n = P->Y.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_PY_ADDR], (uint8_t *)P->Y.p, P->Y.n * 4);
    mpi_ecp_py.p = &acryp0_ram[ECP_PY_ADDR];

    /* transfer Gx/GY/GZ/QX/QY to montmult form */
    op_montmult_func( ACRYP0, ECP_QX_ADDR, ECP_RR_ADDR, ECP_QX_ADDR, MM_MULT);
    op_montmult_func( ACRYP0, ECP_QY_ADDR, ECP_RR_ADDR, ECP_QY_ADDR, MM_MULT);
    op_montmult_func( ACRYP0, ECP_QZ_ADDR, ECP_RR_ADDR, ECP_QZ_ADDR, MM_MULT);
    op_montmult_func( ACRYP0, ECP_PX_ADDR, ECP_RR_ADDR, ECP_PX_ADDR, MM_MULT);
    op_montmult_func( ACRYP0, ECP_PY_ADDR, ECP_RR_ADDR, ECP_PY_ADDR, MM_MULT);

    /* short weierstrass point add */
    op_point_add_func(ACRYP0, &mpi_ecp_qx, &mpi_ecp_qy, &mpi_ecp_qz, &mpi_ecp_px, &mpi_ecp_py, field);

    /* ransfer to Affine coordinates and exit montmult */
    op_ptc_func(ACRYP0, ECP_QX_ADDR, ECP_QY_ADDR, ECP_QZ_ADDR);

    mbedtls_mpi_grow(&R->X, 2 * N_len_n);
    mbedtls_mpi_grow(&R->Y, 2 * N_len_n);
    mbedtls_mpi_grow(&R->Z, 2 * N_len_n);

    memcpy((uint8_t *)&R->X.p[0], (uint8_t *)&acryp0_ram[ECP_QX_ADDR], 2 * N_len_n * 4);
    memcpy((uint8_t *)&R->Y.p[0], (uint8_t *)&acryp0_ram[ECP_QY_ADDR], 2 * N_len_n * 4);
    R->Z.p[0] = 0x1;

    return 0;
}
#endif

/*
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form
 */
#if defined(MBEDTLS_MUL_MONTGOMERY_ALT)
int ecp_mul_mxz( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                 const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;\
    uint32_t N_len_n = 0;
    mpi mpi_ecp_qx, mpi_ecp_qy, mpi_ecp_qz, mpi_ecp_key;
    uint8_t field = FIELD_GFP;

    /* empty the ECC montgomery data space */
    memset((uint8_t *)&acryp0_ram[ECP_QX_ADDR], 0, ECP_LEN * 6 * 4);

    N_len_n = grp->P.n;

    /* montgomery/edwards curve background addr config */
    ecc_ed_mm_background_config(ACRYP0, field, N_len_n, ECP_N_ADDR, ECP_RR_ADDR, ECP_A_ADDR, ECP_N_M2_ADDR);

    /* Qx/Qy/Qz/KEY Init */
    mpi_ecp_qx.n = P->X.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QX_ADDR], (uint8_t *)P->X.p, P->X.n * 4);
    mpi_ecp_qx.p = &acryp0_ram[ECP_QX_ADDR];

    mpi_ecp_qy.n = P->Y.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QY_ADDR], (uint8_t *)P->Y.p, P->Y.n * 4);
    mpi_ecp_qy.p = &acryp0_ram[ECP_QY_ADDR];

    mpi_ecp_qz.n = P->Z.n;
    memcpy((uint8_t *)&acryp0_ram[ECP_QZ_ADDR], (uint8_t *)P->Z.p, P->Z.n * 4);
    mpi_ecp_qz.p = &acryp0_ram[ECP_QZ_ADDR];

    mpi_ecp_key.n = m->n;
    memcpy((uint8_t *)&acryp0_ram[ECP_KEY_ADDR], (uint8_t *)m->p, m->n * 4);
    mpi_ecp_key.p = &acryp0_ram[ECP_KEY_ADDR];

    /* montgomery curve mul to affine */
    op_mmcurve_kmul_func(ACRYP0, &mpi_ecp_qx, &mpi_ecp_qy, &mpi_ecp_qz, &mpi_ecp_key, C_AFF);

    mbedtls_mpi_grow(&R->X, 2 * N_len_n);
    // mbedtls_mpi_grow(&R->Y,2 * N_len_n);
    mbedtls_mpi_grow(&R->Z, 2 * N_len_n);

    memcpy((uint8_t *)&R->X.p[0], (uint8_t *)&acryp0_ram[ECP_QY_ADDR], 2 * N_len_n * 4);
    R->Z.p[0] = 0x1;

cleanup:
    return 0;
}
#endif

#endif /* !MBEDTLS_ECP_ALT */

#endif /* MBEDTLS_ECP_C */
