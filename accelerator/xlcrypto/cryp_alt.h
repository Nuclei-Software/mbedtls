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
#ifndef MBEDTLS_CRYP_ALT_H
#define MBEDTLS_CRYP_ALT_H


#define AES_BUSY_TIMEOUT        ((uint32_t) 0x10011111)
#define DES_BUSY_TIMEOUT        ((uint32_t) 0x10011111)
#define TDES_BUSY_TIMEOUT       ((uint32_t) 0x10011111)
#define GCM_BUSY_TIMEOUT        ((uint32_t) 0x10011111)
#define CCM_BUSY_TIMEOUT        ((uint32_t) 0x10011111)
#define CRYP_TIMEOUT_ERR        (-1)
#define UNUSED                  0



#endif