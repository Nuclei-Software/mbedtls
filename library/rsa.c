/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (c) 2009-2018 Arm Limited. All rights reserved.
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

/*
 *  The following sources were referenced in the design of this implementation
 *  of the RSA algorithm:
 *
 *  [1] A method for obtaining digital signatures and public-key cryptosystems
 *      R Rivest, A Shamir, and L Adleman
 *      http://people.csail.mit.edu/rivest/pubs.html#RSA78
 *
 *  [2] Handbook of Applied Cryptography - 1997, Chapter 8
 *      Menezes, van Oorschot and Vanstone
 *
 *  [3] Malware Guard Extension: Using SGX to Conceal Cache Attacks
 *      Michael Schwarz, Samuel Weiser, Daniel Gruss, Clémentine Maurice and
 *      Stefan Mangard
 *      https://arxiv.org/abs/1702.08719v2
 *
 */

#include "common.h"

#if defined(MBEDTLS_RSA_C)

#ifdef MBEDTLS_ACC_XLCRYPTO_ACRYP_ENABLE
#include "acryp_alt.h"
#endif
#include "mbedtls/rsa.h"
#include "rsa_alt_helpers.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "hash_info.h"

#include <string.h>

#if defined(MBEDTLS_PKCS1_V15) && !defined(__OpenBSD__) && !defined(__NetBSD__)
#include <stdlib.h>
#endif

/* We use MD first if it's available (for compatibility reasons)
 * and "fall back" to PSA otherwise (which needs psa_crypto_init()). */
#if defined(MBEDTLS_PKCS1_V21)
#if !defined(MBEDTLS_MD_C)
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"
#endif /* MBEDTLS_MD_C */
#endif /* MBEDTLS_PKCS1_V21 */

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_RSA_ALT)

#if defined(MBEDTLS_RSA_BACKGROUND_ALT)
extern int mpi_mont_config(const mbedtls_mpi *N, const mbedtls_mpi *P, const mbedtls_mpi *Q);
#endif
#if defined(MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT)
extern int mbedtls_mpi_exp_mod_without_RRmodN( mbedtls_mpi *X, const mbedtls_mpi *A,
                                               const mbedtls_mpi *E, const mbedtls_mpi *N,
                                               uint8_t modulus );
#endif
#if defined(MBEDTLS_BIGNUM_MONTMUL_ALT)
extern int mpi_montmul_alt( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B, const mbedtls_mpi *N);
extern int mpi_montmulself_alt( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N);
#endif
#if defined(RSA_8192)
extern int mbedtls_rsa_get_inv( mbedtls_rsa_context *ctx, mbedtls_mpi *inv_a, const mbedtls_mpi *a);
#endif


int mbedtls_rsa_import( mbedtls_rsa_context *ctx,
                        const mbedtls_mpi *N,
                        const mbedtls_mpi *P, const mbedtls_mpi *Q,
                        const mbedtls_mpi *D, const mbedtls_mpi *E )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ( N != NULL && ( ret = mbedtls_mpi_copy( &ctx->N, N ) ) != 0 ) ||
        ( P != NULL && ( ret = mbedtls_mpi_copy( &ctx->P, P ) ) != 0 ) ||
        ( Q != NULL && ( ret = mbedtls_mpi_copy( &ctx->Q, Q ) ) != 0 ) ||
        ( D != NULL && ( ret = mbedtls_mpi_copy( &ctx->D, D ) ) != 0 ) ||
        ( E != NULL && ( ret = mbedtls_mpi_copy( &ctx->E, E ) ) != 0 ) )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }

    if( N != NULL )
        ctx->len = mbedtls_mpi_size( &ctx->N );

    return( 0 );
}

int mbedtls_rsa_import_raw( mbedtls_rsa_context *ctx,
                            unsigned char const *N, size_t N_len,
                            unsigned char const *P, size_t P_len,
                            unsigned char const *Q, size_t Q_len,
                            unsigned char const *D, size_t D_len,
                            unsigned char const *E, size_t E_len )
{
    int ret = 0;

    if( N != NULL )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->N, N, N_len ) );
        ctx->len = mbedtls_mpi_size( &ctx->N );
    }

    if( P != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->P, P, P_len ) );

    if( Q != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->Q, Q, Q_len ) );

    if( D != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->D, D, D_len ) );

    if( E != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->E, E, E_len ) );

cleanup:

    if( ret != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );

    return( 0 );
}

/*
 * Checks whether the context fields are set in such a way
 * that the RSA primitives will be able to execute without error.
 * It does *not* make guarantees for consistency of the parameters.
 */
static int rsa_check_context( mbedtls_rsa_context const *ctx, int is_priv,
                              int blinding_needed )
{
#if !defined(MBEDTLS_RSA_NO_CRT)
    /* blinding_needed is only used for NO_CRT to decide whether
     * P,Q need to be present or not. */
    ((void) blinding_needed);
#endif

    if( ctx->len != mbedtls_mpi_size( &ctx->N ) ||
        ctx->len > MBEDTLS_MPI_MAX_SIZE )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    /*
     * 1. Modular exponentiation needs positive, odd moduli.
     */

    /* Modular exponentiation wrt. N is always used for
     * RSA public key operations. */
    if( mbedtls_mpi_cmp_int( &ctx->N, 0 ) <= 0 ||
        mbedtls_mpi_get_bit( &ctx->N, 0 ) == 0  )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    /* Modular exponentiation for P and Q is only
     * used for private key operations and if CRT
     * is used. */
    if( is_priv &&
        ( mbedtls_mpi_cmp_int( &ctx->P, 0 ) <= 0 ||
          mbedtls_mpi_get_bit( &ctx->P, 0 ) == 0 ||
          mbedtls_mpi_cmp_int( &ctx->Q, 0 ) <= 0 ||
          mbedtls_mpi_get_bit( &ctx->Q, 0 ) == 0  ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif /* !MBEDTLS_RSA_NO_CRT */

    /*
     * 2. Exponents must be positive
     */

    /* Always need E for public key operations */
    if( mbedtls_mpi_cmp_int( &ctx->E, 0 ) <= 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

#if defined(MBEDTLS_RSA_NO_CRT)
    /* For private key operations, use D or DP & DQ
     * as (unblinded) exponents. */
    if( is_priv && mbedtls_mpi_cmp_int( &ctx->D, 0 ) <= 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
#else
    if( is_priv &&
        ( mbedtls_mpi_cmp_int( &ctx->DP, 0 ) <= 0 ||
          mbedtls_mpi_cmp_int( &ctx->DQ, 0 ) <= 0  ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif /* MBEDTLS_RSA_NO_CRT */

    /* Blinding shouldn't make exponents negative either,
     * so check that P, Q >= 1 if that hasn't yet been
     * done as part of 1. */
#if defined(MBEDTLS_RSA_NO_CRT)
    if( is_priv && blinding_needed &&
        ( mbedtls_mpi_cmp_int( &ctx->P, 0 ) <= 0 ||
          mbedtls_mpi_cmp_int( &ctx->Q, 0 ) <= 0 ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif

    /* It wouldn't lead to an error if it wasn't satisfied,
     * but check for QP >= 1 nonetheless. */
#if !defined(MBEDTLS_RSA_NO_CRT)
    if( is_priv &&
        mbedtls_mpi_cmp_int( &ctx->QP, 0 ) <= 0 )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif

    return( 0 );
}

int mbedtls_rsa_complete( mbedtls_rsa_context *ctx )
{
    int ret = 0;
    int have_N, have_P, have_Q, have_D, have_E;
#if !defined(MBEDTLS_RSA_NO_CRT)
    int have_DP, have_DQ, have_QP;
#endif
    int n_missing, pq_missing, d_missing, is_pub, is_priv;

    have_N = ( mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 );
    have_P = ( mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 );
    have_Q = ( mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 );
    have_D = ( mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 );
    have_E = ( mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0 );

#if !defined(MBEDTLS_RSA_NO_CRT)
    have_DP = ( mbedtls_mpi_cmp_int( &ctx->DP, 0 ) != 0 );
    have_DQ = ( mbedtls_mpi_cmp_int( &ctx->DQ, 0 ) != 0 );
    have_QP = ( mbedtls_mpi_cmp_int( &ctx->QP, 0 ) != 0 );
#endif

    /*
     * Check whether provided parameters are enough
     * to deduce all others. The following incomplete
     * parameter sets for private keys are supported:
     *
     * (1) P, Q missing.
     * (2) D and potentially N missing.
     *
     */

    n_missing  =              have_P &&  have_Q &&  have_D && have_E;
    pq_missing =   have_N && !have_P && !have_Q &&  have_D && have_E;
    d_missing  =              have_P &&  have_Q && !have_D && have_E;
    is_pub     =   have_N && !have_P && !have_Q && !have_D && have_E;

    /* These three alternatives are mutually exclusive */
    is_priv = n_missing || pq_missing || d_missing;

    if( !is_priv && !is_pub )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    /*
     * Step 1: Deduce N if P, Q are provided.
     */

    if( !have_N && have_P && have_Q )
    {
        if( ( ret = mbedtls_mpi_mul_mpi( &ctx->N, &ctx->P,
                                         &ctx->Q ) ) != 0 )
        {
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
        }

        ctx->len = mbedtls_mpi_size( &ctx->N );
    }

    /*
     * Step 2: Deduce and verify all remaining core parameters.
     */

    if( pq_missing )
    {
        ret = mbedtls_rsa_deduce_primes( &ctx->N, &ctx->E, &ctx->D,
                                         &ctx->P, &ctx->Q );
        if( ret != 0 )
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );

    }
    else if( d_missing )
    {
        if( ( ret = mbedtls_rsa_deduce_private_exponent( &ctx->P,
                                                         &ctx->Q,
                                                         &ctx->E,
                                                         &ctx->D ) ) != 0 )
        {
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
        }
    }

    /*
     * Step 3: Deduce all additional parameters specific
     *         to our current RSA implementation.
     */

#if !defined(MBEDTLS_RSA_NO_CRT)
    if( is_priv && ! ( have_DP && have_DQ && have_QP ) )
    {
        ret = mbedtls_rsa_deduce_crt( &ctx->P,  &ctx->Q,  &ctx->D,
                                      &ctx->DP, &ctx->DQ, &ctx->QP );
        if( ret != 0 )
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }
#endif /* MBEDTLS_RSA_NO_CRT */

    /*
     * Step 3: Basic sanity checks
     */

    return( rsa_check_context( ctx, is_priv, 1 ) );
}

int mbedtls_rsa_export_raw( const mbedtls_rsa_context *ctx,
                            unsigned char *N, size_t N_len,
                            unsigned char *P, size_t P_len,
                            unsigned char *Q, size_t Q_len,
                            unsigned char *D, size_t D_len,
                            unsigned char *E, size_t E_len )
{
    int ret = 0;
    int is_priv;

    /* Check if key is private or public */
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
    {
        /* If we're trying to export private parameters for a public key,
         * something must be wrong. */
        if( P != NULL || Q != NULL || D != NULL )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    }

    if( N != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->N, N, N_len ) );

    if( P != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->P, P, P_len ) );

    if( Q != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->Q, Q, Q_len ) );

    if( D != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->D, D, D_len ) );

    if( E != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->E, E, E_len ) );

cleanup:

    return( ret );
}

int mbedtls_rsa_export( const mbedtls_rsa_context *ctx,
                        mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                        mbedtls_mpi *D, mbedtls_mpi *E )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int is_priv;

    /* Check if key is private or public */
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
    {
        /* If we're trying to export private parameters for a public key,
         * something must be wrong. */
        if( P != NULL || Q != NULL || D != NULL )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    }

    /* Export all requested core parameters. */

    if( ( N != NULL && ( ret = mbedtls_mpi_copy( N, &ctx->N ) ) != 0 ) ||
        ( P != NULL && ( ret = mbedtls_mpi_copy( P, &ctx->P ) ) != 0 ) ||
        ( Q != NULL && ( ret = mbedtls_mpi_copy( Q, &ctx->Q ) ) != 0 ) ||
        ( D != NULL && ( ret = mbedtls_mpi_copy( D, &ctx->D ) ) != 0 ) ||
        ( E != NULL && ( ret = mbedtls_mpi_copy( E, &ctx->E ) ) != 0 ) )
    {
        return( ret );
    }

    return( 0 );
}

/*
 * Export CRT parameters
 * This must also be implemented if CRT is not used, for being able to
 * write DER encoded RSA keys. The helper function mbedtls_rsa_deduce_crt
 * can be used in this case.
 */
int mbedtls_rsa_export_crt( const mbedtls_rsa_context *ctx,
                            mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int is_priv;

    /* Check if key is private or public */
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

#if !defined(MBEDTLS_RSA_NO_CRT)
    /* Export all requested blinding parameters. */
    if( ( DP != NULL && ( ret = mbedtls_mpi_copy( DP, &ctx->DP ) ) != 0 ) ||
        ( DQ != NULL && ( ret = mbedtls_mpi_copy( DQ, &ctx->DQ ) ) != 0 ) ||
        ( QP != NULL && ( ret = mbedtls_mpi_copy( QP, &ctx->QP ) ) != 0 ) )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }
#else
    if( ( ret = mbedtls_rsa_deduce_crt( &ctx->P, &ctx->Q, &ctx->D,
                                        DP, DQ, QP ) ) != 0 )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }
#endif

    return( 0 );
}

/*
 * Initialize an RSA context
 */
void mbedtls_rsa_init( mbedtls_rsa_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_rsa_context ) );

    ctx->padding = MBEDTLS_RSA_PKCS_V15;
    ctx->hash_id = MBEDTLS_MD_NONE;

#if defined(MBEDTLS_THREADING_C)
    /* Set ctx->ver to nonzero to indicate that the mutex has been
     * initialized and will need to be freed. */
    ctx->ver = 1;
    mbedtls_mutex_init( &ctx->mutex );
#endif
}

/*
 * Set padding for an existing RSA context
 */
int mbedtls_rsa_set_padding( mbedtls_rsa_context *ctx, int padding,
                             mbedtls_md_type_t hash_id )
{
    switch( padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            break;
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            break;
#endif
        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }

#if defined(MBEDTLS_PKCS1_V21)
    if( ( padding == MBEDTLS_RSA_PKCS_V21 ) &&
        ( hash_id != MBEDTLS_MD_NONE ) )
    {
        /* Just make sure this hash is supported in this build. */
        if( mbedtls_hash_info_psa_from_md( hash_id ) == PSA_ALG_NONE )
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
#endif /* MBEDTLS_PKCS1_V21 */

    ctx->padding = padding;
    ctx->hash_id = hash_id;

    return( 0 );
}

/*
 * Get length in bytes of RSA modulus
 */

size_t mbedtls_rsa_get_len( const mbedtls_rsa_context *ctx )
{
    return( ctx->len );
}


#if defined(MBEDTLS_GENPRIME)

/*
 * Generate an RSA keypair
 *
 * This generation method follows the RSA key pair generation procedure of
 * FIPS 186-4 if 2^16 < exponent < 2^256 and nbits = 2048 or nbits = 3072.
 */
int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi H, G, L;
    int prime_quality = 0;

    /*
     * If the modulus is 1024 bit long or shorter, then the security strength of
     * the RSA algorithm is less than or equal to 80 bits and therefore an error
     * rate of 2^-80 is sufficient.
     */
    if( nbits > 1024 )
        prime_quality = MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;

    mbedtls_mpi_init( &H );
    mbedtls_mpi_init( &G );
    mbedtls_mpi_init( &L );

    if( nbits < 128 || exponent < 3 || nbits % 2 != 0 )
    {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * find primes P and Q with Q < P so that:
     * 1.  |P-Q| > 2^( nbits / 2 - 100 )
     * 2.  GCD( E, (P-1)*(Q-1) ) == 1
     * 3.  E^-1 mod LCM(P-1, Q-1) > 2^( nbits / 2 )
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &ctx->E, exponent ) );

    do
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->P, nbits >> 1,
                                                prime_quality, f_rng, p_rng ) );

        MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->Q, nbits >> 1,
                                                prime_quality, f_rng, p_rng ) );

        /* make sure the difference between p and q is not too small (FIPS 186-4 §B.3.3 step 5.4) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &H, &ctx->P, &ctx->Q ) );
        if( mbedtls_mpi_bitlen( &H ) <= ( ( nbits >= 200 ) ? ( ( nbits >> 1 ) - 99 ) : 0 ) )
            continue;

        /* not required by any standards, but some users rely on the fact that P > Q */
        if( H.s < 0 )
            mbedtls_mpi_swap( &ctx->P, &ctx->Q );

        /* Temporarily replace P,Q by P-1, Q-1 */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &ctx->P, &ctx->P, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &ctx->Q, &ctx->Q, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &H, &ctx->P, &ctx->Q ) );

        /* check GCD( E, (P-1)*(Q-1) ) == 1 (FIPS 186-4 §B.3.1 criterion 2(a)) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->E, &H  ) );
        if( mbedtls_mpi_cmp_int( &G, 1 ) != 0 )
            continue;

        /* compute smallest possible D = E^-1 mod LCM(P-1, Q-1) (FIPS 186-4 §B.3.1 criterion 3(b)) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->P, &ctx->Q ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_div_mpi( &L, NULL, &H, &G ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->D, &ctx->E, &L ) );

        if( mbedtls_mpi_bitlen( &ctx->D ) <= ( ( nbits + 1 ) / 2 ) ) // (FIPS 186-4 §B.3.1 criterion 3(a))
            continue;

        break;
    }
    while( 1 );

    /* Restore P,Q */
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &ctx->P,  &ctx->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &ctx->Q,  &ctx->Q, 1 ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );

    ctx->len = mbedtls_mpi_size( &ctx->N );

#if !defined(MBEDTLS_RSA_NO_CRT)
    /*
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_rsa_deduce_crt( &ctx->P, &ctx->Q, &ctx->D,
                                             &ctx->DP, &ctx->DQ, &ctx->QP ) );
#endif /* MBEDTLS_RSA_NO_CRT */

    /* Double-check */
    MBEDTLS_MPI_CHK( mbedtls_rsa_check_privkey( ctx ) );

cleanup:

    mbedtls_mpi_free( &H );
    mbedtls_mpi_free( &G );
    mbedtls_mpi_free( &L );

    if( ret != 0 )
    {
        mbedtls_rsa_free( ctx );

        if( ( -ret & ~0x7f ) == 0 )
            ret = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_KEY_GEN_FAILED, ret );
        return( ret );
    }

    return( 0 );
}

#endif /* MBEDTLS_GENPRIME */

/*
 * Check a public RSA key
 */
int mbedtls_rsa_check_pubkey( const mbedtls_rsa_context *ctx )
{
    if( rsa_check_context( ctx, 0 /* public */, 0 /* no blinding */ ) != 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( mbedtls_mpi_bitlen( &ctx->N ) < 128 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_get_bit( &ctx->E, 0 ) == 0 ||
        mbedtls_mpi_bitlen( &ctx->E )     < 2  ||
        mbedtls_mpi_cmp_mpi( &ctx->E, &ctx->N ) >= 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}

/*
 * Check for the consistency of all fields in an RSA private key context
 */
int mbedtls_rsa_check_privkey( const mbedtls_rsa_context *ctx )
{
    if( mbedtls_rsa_check_pubkey( ctx ) != 0 ||
        rsa_check_context( ctx, 1 /* private */, 1 /* blinding */ ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_rsa_validate_params( &ctx->N, &ctx->P, &ctx->Q,
                                     &ctx->D, &ctx->E, NULL, NULL ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    else if( mbedtls_rsa_validate_crt( &ctx->P, &ctx->Q, &ctx->D,
                                       &ctx->DP, &ctx->DQ, &ctx->QP ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }
#endif

    return( 0 );
}

/*
 * Check if contexts holding a public and private key match
 */
int mbedtls_rsa_check_pub_priv( const mbedtls_rsa_context *pub,
                                const mbedtls_rsa_context *prv )
{
    if( mbedtls_rsa_check_pubkey( pub )  != 0 ||
        mbedtls_rsa_check_privkey( prv ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_cmp_mpi( &pub->N, &prv->N ) != 0 ||
        mbedtls_mpi_cmp_mpi( &pub->E, &prv->E ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}

/*
 * Do an RSA public key operation
 */
int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;
    mbedtls_mpi T;

    if( rsa_check_context( ctx, 0 /* public */, 0 /* no blinding */ ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T );

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );

    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
#if defined(MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod_without_RRmodN(&T, &T, &ctx->E, &ctx->N, MONTMULT_N_MODULUS) );
#else
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
#endif
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    mbedtls_mpi_free( &T );

    if( ret != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_PUBLIC_FAILED, ret ) );

    return( 0 );
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, count = 0;
    mbedtls_mpi R;

    mbedtls_mpi_init( &R );

    if( ctx->Vf.p != NULL )
    {
        /* We already have blinding values, just update them by squaring */
#if defined(MBEDTLS_BIGNUM_MONTMUL_ALT)
        MBEDTLS_MPI_CHK( mpi_montmulself_alt(&ctx->Vi, &ctx->Vi, &ctx->N) );
        MBEDTLS_MPI_CHK( mpi_montmulself_alt(&ctx->Vf, &ctx->Vf, &ctx->N) );
#else
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &ctx->Vi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vf, &ctx->Vf, &ctx->Vf ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vf, &ctx->Vf, &ctx->N ) );
#endif
        goto cleanup;
    }

    /* Unblinding value: Vf = random number, invertible mod N */
    do {
        if( count++ > 10 )
        {
            ret = MBEDTLS_ERR_RSA_RNG_FAILED;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &ctx->Vf, ctx->len - 1, f_rng, p_rng ) );

        /* Compute Vf^-1 as R * (R Vf)^-1 to avoid leaks from inv_mod. */
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, ctx->len - 1, f_rng, p_rng ) );
#if defined(MBEDTLS_BIGNUM_MONTMUL_ALT)
        MBEDTLS_MPI_CHK( mpi_montmul_alt(&ctx->Vi, &ctx->Vf, &R, &ctx->N) );
#else
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vf, &R ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
#endif

        /* At this point, Vi is invertible mod N if and only if both Vf and R
         * are invertible mod N. If one of them isn't, we don't need to know
         * which one, we just loop and choose new values for both of them.
         * (Each iteration succeeds with overwhelming probability.) */
#if !defined(RSA_8192)
        ret = mbedtls_mpi_inv_mod( &ctx->Vi, &ctx->Vi, &ctx->N );
#else
        ret = mbedtls_rsa_get_inv( ctx, &ctx->Vi, &ctx->Vi );
#endif
        if( ret != 0 && ret != MBEDTLS_ERR_MPI_NOT_ACCEPTABLE )
            goto cleanup;

    } while( ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );

    /* Finish the computation of Vf^-1 = R * (R Vf)^-1 */
#if defined(MBEDTLS_BIGNUM_MONTMUL_ALT)
    MBEDTLS_MPI_CHK( mpi_montmul_alt(&ctx->Vi, &ctx->Vi, &R, &ctx->N) );
#else
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
#endif

    /* Blinding value: Vi = Vf^(-e) mod N
     * (Vi already contains Vf^-1 at this point) */
#if defined(MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod_without_RRmodN(&ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, MONTMULT_N_MODULUS) );
#else
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN ) );
#endif


cleanup:
    mbedtls_mpi_free( &R );

    return( ret );
}

/*
 * Exponent blinding supposed to prevent side-channel attacks using multiple
 * traces of measurements to recover the RSA key. The more collisions are there,
 * the more bits of the key can be recovered. See [3].
 *
 * Collecting n collisions with m bit long blinding value requires 2^(m-m/n)
 * observations on average.
 *
 * For example with 28 byte blinding to achieve 2 collisions the adversary has
 * to make 2^112 observations on average.
 *
 * (With the currently (as of 2017 April) known best algorithms breaking 2048
 * bit RSA requires approximately as much time as trying out 2^112 random keys.
 * Thus in this sense with 28 byte blinding the security is not reduced by
 * side-channel attacks like the one in [3])
 *
 * This countermeasure does not help if the key recovery is possible with a
 * single trace.
 */
#define RSA_EXPONENT_BLINDING 28

/*
 * Do an RSA private key operation
 */
int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;

    /* Temporary holding the result */
    mbedtls_mpi T;

    /* Temporaries holding P-1, Q-1 and the
     * exponent blinding factor, respectively. */
    mbedtls_mpi P1, Q1, R;

#if !defined(MBEDTLS_RSA_NO_CRT)
    /* Temporaries holding the results mod p resp. mod q. */
    mbedtls_mpi TP, TQ;

    /* Temporaries holding the blinded exponents for
     * the mod p resp. mod q computation (if used). */
    mbedtls_mpi DP_blind, DQ_blind;

    /* Pointers to actual exponents to be used - either the unblinded
     * or the blinded ones, depending on the presence of a PRNG. */
    mbedtls_mpi *DP = &ctx->DP;
    mbedtls_mpi *DQ = &ctx->DQ;
#else
    /* Temporary holding the blinded exponent (if used). */
    mbedtls_mpi D_blind;

    /* Pointer to actual exponent to be used - either the unblinded
     * or the blinded one, depending on the presence of a PRNG. */
    mbedtls_mpi *D = &ctx->D;
#endif /* MBEDTLS_RSA_NO_CRT */

    /* Temporaries holding the initial input and the double
     * checked result; should be the same in the end. */
    mbedtls_mpi I, C;

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( rsa_check_context( ctx, 1 /* private key checks */,
                                1 /* blinding on        */ ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    /* MPI Initialization */
    mbedtls_mpi_init( &T );

    mbedtls_mpi_init( &P1 );
    mbedtls_mpi_init( &Q1 );
    mbedtls_mpi_init( &R );

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init( &D_blind );
#else
    mbedtls_mpi_init( &DP_blind );
    mbedtls_mpi_init( &DQ_blind );
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init( &TP ); mbedtls_mpi_init( &TQ );
#endif

    mbedtls_mpi_init( &I );
    mbedtls_mpi_init( &C );

    /* End of MPI initialization */

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );
    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &I, &T ) );

    /*
     * Blinding
     * T = T * Vi mod N
     */
    MBEDTLS_MPI_CHK( rsa_prepare_blinding( ctx, f_rng, p_rng ) );
#if defined(MBEDTLS_BIGNUM_MONTMUL_ALT)
    MBEDTLS_MPI_CHK( mpi_montmul_alt(&T, &T, &ctx->Vi, &ctx->N) );
#else
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vi ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );
#endif

    /*
     * Exponent blinding
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P1, &ctx->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );

#if defined(MBEDTLS_RSA_NO_CRT)
    /*
     * D_blind = ( P - 1 ) * ( Q - 1 ) * R + D
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                     f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &D_blind, &P1, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &D_blind, &D_blind, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &D_blind, &D_blind, &ctx->D ) );

    D = &D_blind;
#else
    /*
     * DP_blind = ( P - 1 ) * R + DP
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                     f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DP_blind, &P1, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &DP_blind, &DP_blind,
                &ctx->DP ) );

    DP = &DP_blind;

    /*
     * DQ_blind = ( Q - 1 ) * R + DQ
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                     f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DQ_blind, &Q1, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &DQ_blind, &DQ_blind,
                &ctx->DQ ) );

    DQ = &DQ_blind;
#endif /* MBEDTLS_RSA_NO_CRT */

#if defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, D, &ctx->N, &ctx->RN ) );
#else
    /*
     * Faster decryption using the CRT
     *
     * TP = input ^ dP mod P
     * TQ = input ^ dQ mod Q
     */
// #if defined(MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT)
//     MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod_without_RRmodN(&TP, &T, DP, &ctx->P, MONTMULT_P_MODULUS) );
//     MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod_without_RRmodN(&TQ, &T, DQ, &ctx->Q, MONTMULT_Q_MODULUS) );
// #else
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &TP, &T, DP, &ctx->P, &ctx->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &TQ, &T, DQ, &ctx->Q, &ctx->RQ ) );
// #endif

    /*
     * T = (TP - TQ) * (Q^-1 mod P) mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T, &TP, &TQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &TP, &T, &ctx->QP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &TP, &ctx->P ) );

    /*
     * T = TQ + T * Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &TP, &T, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T, &TQ, &TP ) );
#endif /* MBEDTLS_RSA_NO_CRT */

    /*
     * Unblind
     * T = T * Vf mod N
     */
#if defined(MBEDTLS_BIGNUM_MONTMUL_ALT)
    MBEDTLS_MPI_CHK( mpi_montmul_alt(&T, &T, &ctx->Vf, &ctx->N) );
#else
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vf ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );
#endif

    /* Verify the result to prevent glitching attacks. */
#if defined(MBEDTLS_BIGNUM_MEXP_WITHOUT_RRMODN_ALT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod_without_RRmodN(&C, &T, &ctx->E, &ctx->N, MONTMULT_N_MODULUS) );
#else
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &C, &T, &ctx->E,
                                          &ctx->N, &ctx->RN ) );
#endif
    if( mbedtls_mpi_cmp_mpi( &C, &I ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    mbedtls_mpi_free( &P1 );
    mbedtls_mpi_free( &Q1 );
    mbedtls_mpi_free( &R );

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free( &D_blind );
#else
    mbedtls_mpi_free( &DP_blind );
    mbedtls_mpi_free( &DQ_blind );
#endif

    mbedtls_mpi_free( &T );

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free( &TP ); mbedtls_mpi_free( &TQ );
#endif

    mbedtls_mpi_free( &C );
    mbedtls_mpi_free( &I );

    if( ret != 0 && ret >= -0x007f )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret ) );

    return( ret );
}

#if defined(MBEDTLS_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
 * \param md_alg    message digest to use
 */
static int mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src,
                      size_t slen, mbedtls_md_type_t md_alg )
{
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;
    unsigned char mask[MBEDTLS_HASH_MAX_SIZE];
#if defined(MBEDTLS_MD_C)
    int ret = 0;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init( &md_ctx );
    md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_md_init( &md_ctx );
    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
        goto exit;

    hlen = mbedtls_md_get_size( md_info );
#else
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_algorithm_t alg = mbedtls_psa_translate_md( md_alg );
    psa_status_t status = PSA_SUCCESS;
    size_t out_len;

    hlen = PSA_HASH_LENGTH( alg );
#endif

    memset( mask, 0, sizeof( mask ) );
    memset( counter, 0, 4 );

    /* Generate and apply dbMask */
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;

#if defined(MBEDTLS_MD_C)
        if( ( ret = mbedtls_md_starts( &md_ctx ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_update( &md_ctx, src, slen ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_update( &md_ctx, counter, 4 ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_finish( &md_ctx, mask ) ) != 0 )
            goto exit;
#else
        if( ( status = psa_hash_setup( &op, alg ) ) != PSA_SUCCESS )
            goto exit;
        if( ( status = psa_hash_update( &op, src, slen ) ) != PSA_SUCCESS )
            goto exit;
        if( ( status = psa_hash_update( &op, counter, 4 ) ) != PSA_SUCCESS )
            goto exit;
        status = psa_hash_finish( &op, mask, sizeof( mask ), &out_len );
        if( status != PSA_SUCCESS )
            goto exit;
#endif

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }

exit:
    mbedtls_platform_zeroize( mask, sizeof( mask ) );
#if defined(MBEDTLS_MD_C)
    mbedtls_md_free( &md_ctx );

    return( ret );
#else
    psa_hash_abort( &op );

    return( mbedtls_md_error_from_psa( status ) );
#endif
}

/**
 * Generate Hash(M') as in RFC 8017 page 43 points 5 and 6.
 *
 * \param hash      the input hash
 * \param hlen      length of the input hash
 * \param salt      the input salt
 * \param slen      length of the input salt
 * \param out       the output buffer - must be large enough for \p md_alg
 * \param md_alg    message digest to use
 */
static int hash_mprime( const unsigned char *hash, size_t hlen,
                        const unsigned char *salt, size_t slen,
                        unsigned char *out, mbedtls_md_type_t md_alg )
{
    const unsigned char zeros[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

#if defined(MBEDTLS_MD_C)
    mbedtls_md_context_t md_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_md_init( &md_ctx );
    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_starts( &md_ctx ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_update( &md_ctx, zeros, sizeof( zeros ) ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_update( &md_ctx, hash, hlen ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_update( &md_ctx, salt, slen ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_finish( &md_ctx, out ) ) != 0 )
        goto exit;

exit:
    mbedtls_md_free( &md_ctx );

    return( ret );
#else
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_algorithm_t alg = mbedtls_psa_translate_md( md_alg );
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED ;
    size_t out_size = PSA_HASH_LENGTH( alg );
    size_t out_len;

    if( ( status = psa_hash_setup( &op, alg ) ) != PSA_SUCCESS )
        goto exit;
    if( ( status = psa_hash_update( &op, zeros, sizeof( zeros ) ) ) != PSA_SUCCESS )
        goto exit;
    if( ( status = psa_hash_update( &op, hash, hlen ) ) != PSA_SUCCESS )
        goto exit;
    if( ( status = psa_hash_update( &op, salt, slen ) ) != PSA_SUCCESS )
        goto exit;
    status = psa_hash_finish( &op, out, out_size, &out_len );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    psa_hash_abort( &op );

    return( mbedtls_md_error_from_psa( status ) );
#endif /* !MBEDTLS_MD_C */
}

/**
 * Compute a hash.
 *
 * \param md_alg    algorithm to use
 * \param input     input message to hash
 * \param ilen      input length
 * \param output    the output buffer - must be large enough for \p md_alg
 */
static int compute_hash( mbedtls_md_type_t md_alg,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output )
{
#if defined(MBEDTLS_MD_C)
    const mbedtls_md_info_t *md_info;

    md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    return( mbedtls_md( md_info, input, ilen, output ) );
#else
    psa_algorithm_t alg = mbedtls_psa_translate_md( md_alg );
    psa_status_t status;
    size_t out_size = PSA_HASH_LENGTH( alg );
    size_t out_len;

    status = psa_hash_compute( alg, input, ilen, output, out_size, &out_len );

    return( mbedtls_md_error_from_psa( status ) );
#endif /* !MBEDTLS_MD_C */
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    size_t olen;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = output;
    unsigned int hlen;

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    hlen = mbedtls_hash_info_get_size( (mbedtls_md_type_t) ctx->hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    /* first comparison checks for overflow */
    if( ilen + 2 * hlen + 2 < ilen || olen < ilen + 2 * hlen + 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    memset( output, 0, olen );

    *p++ = 0;

    /* Generate a random octet string seed */
    if( ( ret = f_rng( p_rng, p, hlen ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_RNG_FAILED, ret ) );

    p += hlen;

    /* Construct DB */
    ret = compute_hash( (mbedtls_md_type_t) ctx->hash_id, label, label_len, p );
    if( ret != 0 )
        return( ret );
    p += hlen;
    p += olen - 2 * hlen - 2 - ilen;
    *p++ = 1;
    if( ilen != 0 )
        memcpy( p, input, ilen );

    /* maskedDB: Apply dbMask to DB */
    if( ( ret = mgf_mask( output + hlen + 1, olen - hlen - 1, output + 1, hlen,
                          ctx->hash_id ) ) != 0 )
        return( ret );

    /* maskedSeed: Apply seedMask to seed */
    if( ( ret = mgf_mask( output + 1, hlen, output + hlen + 1, olen - hlen - 1,
                          ctx->hash_id ) ) != 0 )
        return( ret );

    return( mbedtls_rsa_public(  ctx, output, output ) );
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t nb_pad, olen;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = output;

    olen = ctx->len;

    /* first comparison checks for overflow */
    if( ilen + 11 < ilen || olen < ilen + 11 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    nb_pad = olen - 3 - ilen;

    *p++ = 0;

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    *p++ = MBEDTLS_RSA_CRYPT;

    while( nb_pad-- > 0 )
    {
        int rng_dl = 100;

        do {
            ret = f_rng( p_rng, p, 1 );
        } while( *p == 0 && --rng_dl && ret == 0 );

        /* Check if RNG failed to generate data */
        if( rng_dl == 0 || ret != 0 )
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_RNG_FAILED, ret ) );

        p++;
    }

    *p++ = 0;
    if( ilen != 0 )
        memcpy( p, input, ilen );

    return( mbedtls_rsa_public(  ctx, output, output ) );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Add the message padding, then do an RSA operation
 */
int mbedtls_rsa_pkcs1_encrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_encrypt( ctx, f_rng, p_rng,
                                                        ilen, input, output );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_encrypt( ctx, f_rng, p_rng, NULL, 0,
                                                   ilen, input, output );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t ilen, i, pad_len;
    unsigned char *p, bad, pad_done;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    unsigned char lhash[MBEDTLS_HASH_MAX_SIZE];
    unsigned int hlen;

    /*
     * Parameters sanity checks
     */
    if( ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    ilen = ctx->len;

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    hlen = mbedtls_hash_info_get_size( (mbedtls_md_type_t) ctx->hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    // checking for integer underflow
    if( 2 * hlen + 2 > ilen )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    /*
     * RSA operation
     */
    ret = mbedtls_rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        goto cleanup;

    /*
     * Unmask data and generate lHash
     */
    /* seed: Apply seedMask to maskedSeed */
    if( ( ret = mgf_mask( buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
                          ctx->hash_id ) ) != 0 ||
    /* DB: Apply dbMask to maskedDB */
        ( ret = mgf_mask( buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
                          ctx->hash_id ) ) != 0 )
    {
        goto cleanup;
    }

    /* Generate lHash */
    ret = compute_hash( (mbedtls_md_type_t) ctx->hash_id,
                        label, label_len, lhash );
    if( ret != 0 )
        goto cleanup;

    /*
     * Check contents, in "constant-time"
     */
    p = buf;
    bad = 0;

    bad |= *p++; /* First byte must be 0 */

    p += hlen; /* Skip seed */

    /* Check lHash */
    for( i = 0; i < hlen; i++ )
        bad |= lhash[i] ^ *p++;

    /* Get zero-padding len, but always read till end of buffer
     * (minus one, for the 01 byte) */
    pad_len = 0;
    pad_done = 0;
    for( i = 0; i < ilen - 2 * hlen - 2; i++ )
    {
        pad_done |= p[i];
        pad_len += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
    }

    p += pad_len;
    bad |= *p++ ^ 0x01;

    /*
     * The only information "leaked" is whether the padding was correct or not
     * (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
     * the different error conditions.
     */
    if( bad != 0 )
    {
        ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
        goto cleanup;
    }

    if( ilen - ( p - buf ) > output_max_len )
    {
        ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
        goto cleanup;
    }

    *olen = ilen - (p - buf);
    if( *olen != 0 )
        memcpy( output, p, *olen );
    ret = 0;

cleanup:
    mbedtls_platform_zeroize( buf, sizeof( buf ) );
    mbedtls_platform_zeroize( lhash, sizeof( lhash ) );

    return( ret );
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t ilen;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    ilen = ctx->len;

    if( ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    ret = mbedtls_rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        goto cleanup;

    ret = mbedtls_ct_rsaes_pkcs1_v15_unpadding( buf, ilen,
                                                output, output_max_len, olen );

cleanup:
    mbedtls_platform_zeroize( buf, sizeof( buf ) );

    return( ret );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Do an RSA operation, then remove the message padding
 */
int mbedtls_rsa_pkcs1_decrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len)
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_decrypt( ctx, f_rng, p_rng, olen,
                                                input, output, output_max_len );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_decrypt( ctx, f_rng, p_rng, NULL, 0,
                                           olen, input, output,
                                           output_max_len );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)
static int rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         int saltlen,
                         unsigned char *sig )
{
    size_t olen;
    unsigned char *p = sig;
    unsigned char *salt = NULL;
    size_t slen, min_slen, hlen, offset = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t msb;

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if( ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    if( md_alg != MBEDTLS_MD_NONE )
    {
        /* Gather length of hash to sign */
        size_t exp_hashlen = mbedtls_hash_info_get_size( md_alg );
        if( exp_hashlen == 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( hashlen != exp_hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    hlen = mbedtls_hash_info_get_size( (mbedtls_md_type_t) ctx->hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if (saltlen == MBEDTLS_RSA_SALT_LEN_ANY)
    {
       /* Calculate the largest possible salt length, up to the hash size.
        * Normally this is the hash length, which is the maximum salt length
        * according to FIPS 185-4 §5.5 (e) and common practice. If there is not
        * enough room, use the maximum salt length that fits. The constraint is
        * that the hash length plus the salt length plus 2 bytes must be at most
        * the key length. This complies with FIPS 186-4 §5.5 (e) and RFC 8017
        * (PKCS#1 v2.2) §9.1.1 step 3. */
        min_slen = hlen - 2;
        if( olen < hlen + min_slen + 2 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        else if( olen >= hlen + hlen + 2 )
            slen = hlen;
        else
            slen = olen - hlen - 2;
    }
    else if ( (saltlen < 0) || (saltlen + hlen + 2 > olen) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
    else
    {
        slen = (size_t) saltlen;
    }

    memset( sig, 0, olen );

    /* Note: EMSA-PSS encoding is over the length of N - 1 bits */
    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;
    p += olen - hlen - slen - 2;
    *p++ = 0x01;

    /* Generate salt of length slen in place in the encoded message */
    salt = p;
    if( ( ret = f_rng( p_rng, salt, slen ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_RNG_FAILED, ret ) );

    p += slen;

    /* Generate H = Hash( M' ) */
    ret = hash_mprime( hash, hashlen, salt, slen, p, ctx->hash_id );
    if( ret != 0 )
        return( ret );

    /* Compensate for boundary condition when applying mask */
    if( msb % 8 == 0 )
        offset = 1;

    /* maskedDB: Apply dbMask to DB */
    ret = mgf_mask( sig + offset, olen - hlen - 1 - offset, p, hlen,
                    ctx->hash_id );
    if( ret != 0 )
        return( ret );

    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;
    sig[0] &= 0xFF >> ( olen * 8 - msb );

    p += hlen;
    *p++ = 0xBC;

    return mbedtls_rsa_private( ctx, f_rng, p_rng, sig, sig );
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function with
 * the option to pass in the salt length.
 */
int mbedtls_rsa_rsassa_pss_sign_ext( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         int saltlen,
                         unsigned char *sig )
{
    return rsa_rsassa_pss_sign( ctx, f_rng, p_rng, md_alg,
                                hashlen, hash, saltlen, sig );
}


/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
 */
int mbedtls_rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
    return rsa_rsassa_pss_sign( ctx, f_rng, p_rng, md_alg,
                                hashlen, hash, MBEDTLS_RSA_SALT_LEN_ANY, sig );
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 */

/* Construct a PKCS v1.5 encoding of a hashed message
 *
 * This is used both for signature generation and verification.
 *
 * Parameters:
 * - md_alg:  Identifies the hash algorithm used to generate the given hash;
 *            MBEDTLS_MD_NONE if raw data is signed.
 * - hashlen: Length of hash. Must match md_alg if that's not NONE.
 * - hash:    Buffer containing the hashed message or the raw data.
 * - dst_len: Length of the encoded message.
 * - dst:     Buffer to hold the encoded message.
 *
 * Assumptions:
 * - hash has size hashlen.
 * - dst points to a buffer of size at least dst_len.
 *
 */
static int rsa_rsassa_pkcs1_v15_encode( mbedtls_md_type_t md_alg,
                                        unsigned int hashlen,
                                        const unsigned char *hash,
                                        size_t dst_len,
                                        unsigned char *dst )
{
    size_t oid_size  = 0;
    size_t nb_pad    = dst_len;
    unsigned char *p = dst;
    const char *oid  = NULL;

    /* Are we signing hashed or raw data? */
    if( md_alg != MBEDTLS_MD_NONE )
    {
        unsigned char md_size = mbedtls_hash_info_get_size( md_alg );
        if( md_size == 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( mbedtls_oid_get_oid_by_md( md_alg, &oid, &oid_size ) != 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( hashlen != md_size )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        /* Double-check that 8 + hashlen + oid_size can be used as a
         * 1-byte ASN.1 length encoding and that there's no overflow. */
        if( 8 + hashlen + oid_size  >= 0x80         ||
            10 + hashlen            <  hashlen      ||
            10 + hashlen + oid_size <  10 + hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        /*
         * Static bounds check:
         * - Need 10 bytes for five tag-length pairs.
         *   (Insist on 1-byte length encodings to protect against variants of
         *    Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
         * - Need hashlen bytes for hash
         * - Need oid_size bytes for hash alg OID.
         */
        if( nb_pad < 10 + hashlen + oid_size )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        nb_pad -= 10 + hashlen + oid_size;
    }
    else
    {
        if( nb_pad < hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        nb_pad -= hashlen;
    }

    /* Need space for signature header and padding delimiter (3 bytes),
     * and 8 bytes for the minimal padding */
    if( nb_pad < 3 + 8 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    nb_pad -= 3;

    /* Now nb_pad is the amount of memory to be filled
     * with padding, and at least 8 bytes long. */

    /* Write signature header and padding */
    *p++ = 0;
    *p++ = MBEDTLS_RSA_SIGN;
    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    /* Are we signing raw data? */
    if( md_alg == MBEDTLS_MD_NONE )
    {
        memcpy( p, hash, hashlen );
        return( 0 );
    }

    /* Signing hashed data, add corresponding ASN.1 structure
     *
     * DigestInfo ::= SEQUENCE {
     *   digestAlgorithm DigestAlgorithmIdentifier,
     *   digest Digest }
     * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
     * Digest ::= OCTET STRING
     *
     * Schematic:
     * TAG-SEQ + LEN [ TAG-SEQ + LEN [ TAG-OID  + LEN [ OID  ]
     *                                 TAG-NULL + LEN [ NULL ] ]
     *                 TAG-OCTET + LEN [ HASH ] ]
     */
    *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
    *p++ = (unsigned char)( 0x08 + oid_size + hashlen );
    *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
    *p++ = (unsigned char)( 0x04 + oid_size );
    *p++ = MBEDTLS_ASN1_OID;
    *p++ = (unsigned char) oid_size;
    memcpy( p, oid, oid_size );
    p += oid_size;
    *p++ = MBEDTLS_ASN1_NULL;
    *p++ = 0x00;
    *p++ = MBEDTLS_ASN1_OCTET_STRING;
    *p++ = (unsigned char) hashlen;
    memcpy( p, hash, hashlen );
    p += hashlen;

    /* Just a sanity-check, should be automatic
     * after the initial bounds check. */
    if( p != dst + dst_len )
    {
        mbedtls_platform_zeroize( dst, dst_len );
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    return( 0 );
}

/*
 * Do an RSA operation to sign the message digest
 */
int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *sig_try = NULL, *verif = NULL;

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if( ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    /*
     * Prepare PKCS1-v1.5 encoding (padding and hash identifier)
     */

    if( ( ret = rsa_rsassa_pkcs1_v15_encode( md_alg, hashlen, hash,
                                             ctx->len, sig ) ) != 0 )
        return( ret );

    /* Private key operation
     *
     * In order to prevent Lenstra's attack, make the signature in a
     * temporary buffer and check it before returning it.
     */

    sig_try = mbedtls_calloc( 1, ctx->len );
    if( sig_try == NULL )
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );

    verif = mbedtls_calloc( 1, ctx->len );
    if( verif == NULL )
    {
        mbedtls_free( sig_try );
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }

    MBEDTLS_MPI_CHK( mbedtls_rsa_private( ctx, f_rng, p_rng, sig, sig_try ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_public( ctx, sig_try, verif ) );

    if( mbedtls_ct_memcmp( verif, sig, ctx->len ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto cleanup;
    }

    memcpy( sig, sig_try, ctx->len );

cleanup:
    mbedtls_platform_zeroize( sig_try, ctx->len );
    mbedtls_platform_zeroize( verif, ctx->len );
    mbedtls_free( sig_try );
    mbedtls_free( verif );

    if( ret != 0 )
        memset( sig, '!', ctx->len );
    return( ret );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Do an RSA operation to sign the message digest
 */
int mbedtls_rsa_pkcs1_sign( mbedtls_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    mbedtls_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsassa_pkcs1_v15_sign( ctx, f_rng, p_rng,
                                                      md_alg, hashlen, hash, sig );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsassa_pss_sign( ctx, f_rng, p_rng, md_alg,
                                                hashlen, hash, sig );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_rsa_context *ctx,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               mbedtls_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t siglen;
    unsigned char *p;
    unsigned char *hash_start;
    unsigned char result[MBEDTLS_HASH_MAX_SIZE];
    unsigned int hlen;
    size_t observed_salt_len, msb;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE] = {0};

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    siglen = ctx->len;

    if( siglen < 16 || siglen > sizeof( buf ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    ret = mbedtls_rsa_public(  ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( buf[siglen - 1] != 0xBC )
        return( MBEDTLS_ERR_RSA_INVALID_PADDING );

    if( md_alg != MBEDTLS_MD_NONE )
    {
        /* Gather length of hash to sign */
        size_t exp_hashlen = mbedtls_hash_info_get_size( md_alg );
        if( exp_hashlen == 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( hashlen != exp_hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    hlen = mbedtls_hash_info_get_size( mgf1_hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    /*
     * Note: EMSA-PSS verification is over the length of N - 1 bits
     */
    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;

    if( buf[0] >> ( 8 - siglen * 8 + msb ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    /* Compensate for boundary condition when applying mask */
    if( msb % 8 == 0 )
    {
        p++;
        siglen -= 1;
    }

    if( siglen < hlen + 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    hash_start = p + siglen - hlen - 1;

    ret = mgf_mask( p, siglen - hlen - 1, hash_start, hlen, mgf1_hash_id );
    if( ret != 0 )
        return( ret );

    buf[0] &= 0xFF >> ( siglen * 8 - msb );

    while( p < hash_start - 1 && *p == 0 )
        p++;

    if( *p++ != 0x01 )
        return( MBEDTLS_ERR_RSA_INVALID_PADDING );

    observed_salt_len = hash_start - p;

    if( expected_salt_len != MBEDTLS_RSA_SALT_LEN_ANY &&
        observed_salt_len != (size_t) expected_salt_len )
    {
        return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }

    /*
     * Generate H = Hash( M' )
     */
    ret = hash_mprime( hash, hashlen, p, observed_salt_len,
                       result, mgf1_hash_id );
    if( ret != 0 )
        return( ret );

    if( memcmp( hash_start, result, hlen ) != 0 )
        return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

    return( 0 );
}

/*
 * Simplified PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int mbedtls_rsa_rsassa_pss_verify( mbedtls_rsa_context *ctx,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig )
{
    mbedtls_md_type_t mgf1_hash_id;
    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    mgf1_hash_id = ( ctx->hash_id != MBEDTLS_MD_NONE )
                             ? (mbedtls_md_type_t) ctx->hash_id
                             : md_alg;

    return( mbedtls_rsa_rsassa_pss_verify_ext( ctx,
                                               md_alg, hashlen, hash,
                                               mgf1_hash_id,
                                               MBEDTLS_RSA_SALT_LEN_ANY,
                                               sig ) );

}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
 */
int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx,
                                 mbedtls_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig )
{
    int ret = 0;
    size_t sig_len;
    unsigned char *encoded = NULL, *encoded_expected = NULL;

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    sig_len = ctx->len;

    /*
     * Prepare expected PKCS1 v1.5 encoding of hash.
     */

    if( ( encoded          = mbedtls_calloc( 1, sig_len ) ) == NULL ||
        ( encoded_expected = mbedtls_calloc( 1, sig_len ) ) == NULL )
    {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto cleanup;
    }

    if( ( ret = rsa_rsassa_pkcs1_v15_encode( md_alg, hashlen, hash, sig_len,
                                             encoded_expected ) ) != 0 )
        goto cleanup;

    /*
     * Apply RSA primitive to get what should be PKCS1 encoded hash.
     */

    ret = mbedtls_rsa_public( ctx, sig, encoded );
    if( ret != 0 )
        goto cleanup;

    /*
     * Compare
     */

    if( ( ret = mbedtls_ct_memcmp( encoded, encoded_expected,
                                              sig_len ) ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:

    if( encoded != NULL )
    {
        mbedtls_platform_zeroize( encoded, sig_len );
        mbedtls_free( encoded );
    }

    if( encoded_expected != NULL )
    {
        mbedtls_platform_zeroize( encoded_expected, sig_len );
        mbedtls_free( encoded_expected );
    }

    return( ret );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Do an RSA operation and check the message digest
 */
int mbedtls_rsa_pkcs1_verify( mbedtls_rsa_context *ctx,
                      mbedtls_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig )
{
    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsassa_pkcs1_v15_verify( ctx, md_alg,
                                                        hashlen, hash, sig );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsassa_pss_verify( ctx, md_alg,
                                                  hashlen, hash, sig );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

/*
 * Copy the components of an RSA key
 */
int mbedtls_rsa_copy( mbedtls_rsa_context *dst, const mbedtls_rsa_context *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    dst->len = src->len;

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->N, &src->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->E, &src->E ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->D, &src->D ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->P, &src->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Q, &src->Q ) );

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DP, &src->DP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DQ, &src->DQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->QP, &src->QP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RP, &src->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RQ, &src->RQ ) );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RN, &src->RN ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vi, &src->Vi ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vf, &src->Vf ) );

    dst->padding = src->padding;
    dst->hash_id = src->hash_id;

cleanup:
    if( ret != 0 )
        mbedtls_rsa_free( dst );

    return( ret );
}

/*
 * Free the components of an RSA key
 */
void mbedtls_rsa_free( mbedtls_rsa_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_mpi_free( &ctx->Vi );
    mbedtls_mpi_free( &ctx->Vf );
    mbedtls_mpi_free( &ctx->RN );
    mbedtls_mpi_free( &ctx->D  );
    mbedtls_mpi_free( &ctx->Q  );
    mbedtls_mpi_free( &ctx->P  );
    mbedtls_mpi_free( &ctx->E  );
    mbedtls_mpi_free( &ctx->N  );

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free( &ctx->RQ );
    mbedtls_mpi_free( &ctx->RP );
    mbedtls_mpi_free( &ctx->QP );
    mbedtls_mpi_free( &ctx->DQ );
    mbedtls_mpi_free( &ctx->DP );
#endif /* MBEDTLS_RSA_NO_CRT */

#if defined(MBEDTLS_THREADING_C)
    /* Free the mutex, but only if it hasn't been freed already. */
    if( ctx->ver != 0 )
    {
        mbedtls_mutex_free( &ctx->mutex );
        ctx->ver = 0;
    }
#endif
}

#endif /* !MBEDTLS_RSA_ALT */

#if defined(MBEDTLS_SELF_TEST)

#include "mbedtls/sha1.h"

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

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
int mbedtls_rsa_self_test( int verbose )
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
        mbedtls_printf( "  RSA key validation: " );

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

#define KEY_LEN_RSA_8192 1024

#define RSA_N_RSA_8192  "ceb90313a5c86992c73ca390b3d341e0" \
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

#define RSA_D_RSA_8192  "097343c4be2b6f481a7b972ea249e215" \
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

#define RSA_P_RSA_8192  "E91E42639F1E0C653EE2FB44337DFB23"  \
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

#define RSA_Q_RSA_8192  "E3037E208CA28DAB5535A958CB77258D"  \
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
    unsigned char rsa_ciphertext[KEY_LEN_RSA_8192];
#if defined(MBEDTLS_SHA1_C)
    unsigned char sha1sum[20];
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init( &K );
    mbedtls_rsa_init( &rsa );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_N_RSA_8192  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, &K, NULL, NULL, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_P_RSA_8192  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, &K, NULL, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_Q_RSA_8192  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, &K, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_D_RSA_8192  ) );
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
