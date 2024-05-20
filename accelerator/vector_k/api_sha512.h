#include <stdint.h>

#ifndef __API_SHA512__
#define __API_SHA512__

void sha512_transform_zvknhb_zvkb(unsigned long int * state,
                                  const unsigned char *data,
                                  int num_blocks);

#endif // __API_SHA512__
