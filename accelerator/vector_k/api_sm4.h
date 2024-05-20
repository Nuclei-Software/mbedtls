
#ifndef __API_SM4_H__
#define __API_SM4_H__

void sm4_expandkey_zvksed_zvkb(const unsigned char user_key[16],
                               unsigned int rkey_enc[32],
                               unsigned int rkey_dec[32]);

void sm4_crypt_zvksed_zvkb(const unsigned int rkey[32],
                           const unsigned char in[16],
                           unsigned char out[16]);

#endif

