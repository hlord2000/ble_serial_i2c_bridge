#ifndef I2C_PERIPHERAL_H__
#define I2C_PERIPHERAL_H__
#include <stdint.h>

extern struct k_msgq i2c_msgq;

struct __attribute__((packed)) i2c_packet {
	uint8_t nonce[8];
	uint8_t ciphertext[8];
};

enum i2c_cmds {
	I2C_REG_STATUS,
	I2C_REG_DEV_ID,
	I2C_REG_ADVERTISING,
	I2C_REG_CONN_PARAM,
	I2C_REG_POWER,
	I2C_REG_TX_BUF,
	I2C_REG_TX_BUF_LEN,
	I2C_REG_RX_BUF,
	I2C_REG_RX_BUF_LEN,
	I2C_REG_END,
};

struct i2c_cmd_reg {
	uint8_t data[16];
	bool read;
	bool write;
};

#endif
