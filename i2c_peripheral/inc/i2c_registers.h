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

struct i2c_cmd_reg {
    bool read;
    bool write;
    union {
        uint8_t data[DATA_SIZE_BYTES];
        struct ring_buf ring_data;
    };
    bool is_ring_buffer;
    uint8_t ring_buffer_mem[RING_BUF_SIZE];
};

extern struct i2c_cmd_reg command_registers[I2C_REG_END];

void write_rx_register(uint8_t *buf);

#endif
