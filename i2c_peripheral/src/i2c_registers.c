#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "i2c_registers.h"
#include "i2c_packet.h"
#include "ble_packet.h"

LOG_MODULE_REGISTER(i2c_registers);

extern struct k_msgq i2c_msgq;

struct i2c_cmd_reg command_registers[I2C_REG_END] = {
	{ /* I2C_REG_STATUS */
		.data = {0x13, 0x37},
		.read = true,
		.write = false,
	},
	{ /* I2C_REG_DEV_ID */
		.data = {0xBE, 0xEF},
		.read = true,
		.write = false,
	}, 
	{ /* I2C_REG_ADVERTISING */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_CONN_PARAM */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_CONN_POWER */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_TX_BUF */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_RX_BUF */
		.data = {},
		.read = true,
		.write = true,
	}, 
};

static int i2c_reg_status_handler(struct i2c_reg_packet *packet) {
	LOG_INF("Status register packet");
	return 0;
}

static int i2c_reg_dev_id_handler(struct i2c_reg_packet *packet) {
	LOG_INF("Device ID packet");
	return 0;
}

static int i2c_reg_advertising_handler(struct i2c_reg_packet *packet) {
	LOG_INF("Advertising packet");
	if (packet->read) {
		return 0;
	}
}

static int i2c_reg_connection_handler(struct i2c_reg_packet *packet) {
	LOG_INF("Connection packet");
	if (packet->read) {
		return 0;
	}
}

static int i2c_reg_power_handler(struct i2c_reg_packet *packet) {
	LOG_INF("Power packet");
	if (packet->read) {
		return 0;
	}
}

static int i2c_reg_tx_buf_handler(struct i2c_reg_packet *packet) {
	LOG_INF("TX buf packet");
	if (packet->read) {
		return 0;
	} else {
		memcpy(command_registers[I2C_REG_TX_BUF].data, packet->plaintext, sizeof(packet->plaintext));

		struct ble_packet plaintext;
		memcpy(plaintext.plaintext, packet->plaintext, sizeof(packet->plaintext));
		plaintext.magic = BLE_PACKET_MAGIC;

		struct ble_enc_packet ciphertext;
		encrypt_ble_packet(&plaintext, &ciphertext);

		i2c_bridge_transmit(&ciphertext);
	}
}

static int i2c_reg_rx_buf_handler(struct i2c_reg_packet *packet) {
	LOG_INF("RX buf packet");
	if (packet->read) {
		// CLEAR INT GPIO
		return 0;
	}
}

static int (*i2c_reg_handlers[])(struct i2c_reg_packet *) = {
    i2c_reg_status_handler,
    i2c_reg_dev_id_handler,
    i2c_reg_advertising_handler,
	i2c_reg_connection_handler,
	i2c_reg_power_handler,
    i2c_reg_tx_buf_handler,
    i2c_reg_rx_buf_handler,
};

static bool is_read_command(uint8_t *data) {
	for (int i = 0; i < I2C_PACKET_SIZE_BYTES; i++) {
	  if (data[i] != 0) {
	  	return false;
	  }
	}
	return true;
}


int i2c_register_handler(void) {
	LOG_INF("Beginning secure I2C -> NUS bridge");

	struct i2c_reg_packet plaintext;
	while (true) {
		k_msgq_get(&i2c_msgq, &plaintext, K_FOREVER);
		plaintext.read = is_read_command(plaintext.plaintext);
		i2c_reg_handlers[plaintext.reg](&plaintext);
	}
}

void write_rx_register(uint8_t *buf) {
	memcpy(command_registers[I2C_REG_RX_BUF].data, buf, DATA_SIZE_BYTES);
	// SET INT GPIO
}

#define THREAD_STACK_SIZE 2048 
#define THREAD_PRIORITY 5

K_THREAD_DEFINE(i2c_register_thread, THREAD_STACK_SIZE,
                i2c_register_handler, NULL, NULL, NULL,
                THREAD_PRIORITY, 0, 0);
