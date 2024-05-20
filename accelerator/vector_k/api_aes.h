
#include <stdint.h>

#ifndef __API_AES_H__
#define __API_AES_H__

/*!
@brief single-block AES encrypt function
@param [in]  rk - The expanded key schedule
@param [in]  input - Input plaintext
@param [out] output - Output cipher text.
*/
void aes_encrypt_zvkned(const unsigned int *rk,
                        const unsigned char input[16],
                        unsigned char output[16]);

/*!
@brief single-block AES decrypt function
@param [in]  rk - The expanded key schedule
@param [in]  input - Input plaintext
@param [out] output - Output cipher text.
*/
void aes_decrypt_zvkned(const unsigned int *rk,
                        const unsigned char input[16],
                        unsigned char output[16]);

/*!
@brief AES-CBC mode encrypt function on full blocks.
@param [in]  rk - The expanded key schedule
@param [in]  input - Input plaintext
@param [out] output - Output cipher text.
@param [in]  length - The length of input plaintext
@param [in]  iv - Initialization vector (updated after use)
*/
void aes_cbc_encrypt_zvkned(const unsigned int *rk,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t length,
                            unsigned char iv[16]);

/*!
@brief AES-CBC mode decrypt function on full blocks.
@param [in]  rk - The expanded key schedule
@param [in]  input - Input plaintext
@param [out] output - Output cipher text.
@param [in]  length - The length of input plaintext
@param [in]  iv - Initialization vector (updated after use)
*/
void aes_cbc_decrypt_zvkned(const unsigned int *rk,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t length,
                            unsigned char iv[16]);

#endif

//! @}
