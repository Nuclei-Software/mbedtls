
/*!
@defgroup crypto_hash_sm3 Crypto Hash SM3
@{
*/

#include <stddef.h>
#include <stdint.h>

#include "share/util.h"

#ifndef __API_SM3__
#define __API_SM3__

// Hashes `message` with `len` bytes with SM3 and stores it to `hash`
void sm3_hash(uint8_t hash[32], const uint8_t *message, size_t len);
void sm3_compress(uint32_t s[24]);
//! @}

#endif // __API_SM3__
