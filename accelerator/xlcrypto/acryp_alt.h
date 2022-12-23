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
#ifndef MBEDTLS_ACRYP_ALT_H
#define MBEDTLS_ACRYP_ALT_H

#define MONTMULT_N_MODULUS          0
#define MONTMULT_P_MODULUS          1
#define MONTMULT_Q_MODULUS          2

int mbedtls_mpi_self_test_alt( int verbose );
int mbedtls_rsa8192_self_test( int verbose );

#endif