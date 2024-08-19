#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <errno.h>
#include <stdio.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/settings/settings.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#include "crypto.h"
#include "shared_keys.h"

LOG_MODULE_REGISTER(crypto);

#define AES_BLOCK_SIZE (16)

static psa_key_id_t key_id;

#warning "The encryption key for I2C is stored in RAM!"
static int import_input_key(void) {
	psa_status_t status;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the input key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CTR);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);

	/* Import the master key into the keystore */
	status = psa_import_key(&key_attributes,
				shared_key_i2c,
				sizeof(shared_key_i2c),
				&key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("PSA import key fail (err: %d)", status);
		return status;
	}

	psa_set_key_id(&key_attributes, PSA_KEY_ID_USER_MIN);

	psa_reset_key_attributes(&key_attributes);

	return 0;
}

int encrypt_ctr_aes(uint8_t *iv_buf, uint8_t *plaintext, size_t plain_len, uint8_t *ciphertext,
					size_t cipher_len) {
	uint32_t olen;
	psa_status_t status;
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

	LOG_INF("Encrypting using AES CTR MODE...");

	/* Setup the encryption operation */
	status = psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CTR);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_encrypt_setup failed! (Error: %d)", status);
		return status;
	}

	if (iv_buf == NULL) {
		uint8_t local_iv_buf[16] = {0};
		iv_buf = local_iv_buf;
	}

	/* Generate a random IV */
	status = psa_cipher_generate_iv(&operation, iv_buf, 8,
					&olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_generate_iv failed! (Error: %d)", status);
		return status;
	}

	/* Perform the encryption */
	status = psa_cipher_update(&operation,
							   plaintext,
							   plain_len,
							   ciphertext,
							   cipher_len,
							   &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_update failed! (Error: %d)", status);
		return status;
	}

	/* Finalize encryption */
	status = psa_cipher_finish(&operation,
							   ciphertext + olen,
							   cipher_len - olen,
							   &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_finish failed! (Error: %d)", status);
		return status;
	}

	/* Clean up cipher operation context */
	status = psa_cipher_abort(&operation);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_abort failed! (Error: %d)", status);
		return status;
	}

	LOG_INF("Encryption successful!\r\n");
	LOG_HEXDUMP_INF(iv_buf, sizeof(iv_buf), "IV");
	LOG_HEXDUMP_INF(plaintext, plain_len, "Plaintext");
	LOG_HEXDUMP_INF(ciphertext, cipher_len, "Encrypted text");

	return 0;
}

int decrypt_ctr_aes(uint8_t *iv_buf, uint8_t *ciphertext, size_t cipher_len, uint8_t *plaintext, 
					size_t plain_len) {
	uint32_t olen;
	psa_status_t status;
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

	LOG_INF("Decrypting using AES CTR MODE...");

	/* Setup the decryption operation */
	status = psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CTR);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_decrypt_setup failed! (Error: %d)", status);
		return status;
	}

	/* Set the IV to the one generated during encryption */
	status = psa_cipher_set_iv(&operation, iv_buf, AES_BLOCK_SIZE);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_set_iv failed! (Error: %d)", status);
		return status;
	}

	/* Perform the decryption */
	status = psa_cipher_update(&operation,
							   ciphertext,
							   cipher_len,
							   plaintext,
							   plain_len, &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_update failed! (Error: %d)", status);
		return status;
	}

	/* Finalize the decryption */
	status = psa_cipher_finish(&operation,
							   plaintext + olen,
							   plain_len - olen,
							   &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_finish failed! (Error: %d)", status);
		return status;
	}

	LOG_HEXDUMP_INF(plaintext, plain_len, "Decrypted text");

	/* Clean up cipher operation context */
	status = psa_cipher_abort(&operation);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_abort failed! (Error: %d)", status);
		return status;
	}

	return 0;
}

static int crypto_init(void) {
	psa_status_t status;

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		LOG_ERR("PSA init fail (err: %d)", status);
		return status;
	}

	status = import_input_key();
	if (status != PSA_SUCCESS) {
		LOG_ERR("PSA import input key fail (err: %d)", status);
		return status;
	}

	return 0;
}

SYS_INIT(crypto_init, APPLICATION, 90);
