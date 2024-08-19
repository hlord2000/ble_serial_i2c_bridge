#ifndef CRYPTO_H__
#define CRYPTO_H__
#include <stdlib.h>
#include <stdint.h>

int encrypt_ctr_aes(uint8_t *iv_buf, uint8_t *plaintext, size_t plain_len, uint8_t *ciphertext, 
					size_t cipher_len);
int decrypt_ctr_aes(uint8_t *iv_buf, uint8_t *ciphertext, size_t cipher_len, uint8_t *plaintext, 
					size_t plain_len);

#endif
