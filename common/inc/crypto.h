#ifndef CRYPTO_H__
#define CRYPTO_H__
#include "i2c_packet.h"
#include "ble_packet.h"

int encrypt_i2c_packet(struct i2c_reg_packet *plaintext, struct i2c_reg_enc_packet *encrypted);
int decrypt_i2c_packet(struct i2c_reg_packet *plaintext, struct i2c_reg_enc_packet *encrypted);

int encrypt_ble_packet(struct ble_packet *plaintext, struct ble_enc_packet *encrypted);
int decrypt_ble_packet(struct ble_packet *plaintext, struct ble_enc_packet *encrypted);

#endif
