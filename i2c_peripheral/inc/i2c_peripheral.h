#ifndef I2C_PERIPHERAL_H__
#define I2C_PERIPHERAL_H__
#include <stdint.h>
#include <stdbool.h>
#include "i2c_packet.h"

extern struct k_msgq i2c_msgq;

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
	uint8_t data[DATA_SIZE_BYTES];
	bool read;
	bool write;
};

#endif
