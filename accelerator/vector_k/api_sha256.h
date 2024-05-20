#include <stdint.h>
#include <stddef.h>

#ifndef __API_SHA256__
#define __API_SHA256__

void sha256_transform_zvknha_or_zvknhb_zvkb(unsigned int state[8],
                                            const unsigned char *data,
                                            int num_blocks);

/*! @} */

#endif // __API_SHA256__
