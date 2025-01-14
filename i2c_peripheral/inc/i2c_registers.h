#ifndef I2C_REGISTERS_H__
#define I2C_REGISTERS_H__
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <zephyr/sys/ring_buffer.h>
#include "i2c_packet.h"
#include "i2c_register_map.h"

extern struct k_msgq i2c_msqg;

#define RING_BUF_SIZE 1024

enum reg_permissions {
	REG_PERM_NONE = 0,
	REG_PERM_READ = BIT(0),
	REG_PERM_WRITE = BIT(1),
	REG_PERM_RW = GENMASK(1, 0),
};
enum reg_types {
	REG_TYPE_NORMAL = 0,
	REG_TYPE_RINGBUF,
	REG_TYPE_VIRTUAL,
};

enum int_types {
	INT_TYPE_BLE_RX = BIT(0),
	INT_TYPE_BLE_CONN_LOST = BIT(1),
};

struct i2c_cmd_reg {
	enum reg_permissions permission;
	enum reg_types type;

	uint8_t data[DATA_SIZE_BYTES];

	struct ring_buf ring_data;
    uint8_t *ring_buffer_mem;
};

extern struct i2c_cmd_reg command_registers[I2C_REG_END];

void write_rx_register(uint8_t *buf);

#endif
