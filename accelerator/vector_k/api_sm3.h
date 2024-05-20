#include <stddef.h>

#ifndef __API_SM3__
#define __API_SM3__

void sm3_transform_zvksh_zvkb(unsigned int state[8],
                              const unsigned char *data,
                              int num_blocks);

#endif // __API_SM3__
