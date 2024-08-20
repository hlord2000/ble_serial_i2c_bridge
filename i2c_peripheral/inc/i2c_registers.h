#ifndef I2C_REGISTERS_H__
#define I2C_REGISTERS_H__
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "i2c_packet.h"
#include "i2c_register_map.h"

extern struct k_msgq i2c_msqg;

struct i2c_cmd_reg {
	bool read;
	bool write;
	uint8_t data[DATA_SIZE_BYTES];
};

extern struct i2c_cmd_reg command_registers[I2C_REG_END];

void write_rx_register(uint8_t *buf);

#endif
