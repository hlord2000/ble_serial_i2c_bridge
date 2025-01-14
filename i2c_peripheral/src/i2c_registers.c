#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>

#include "crypto.h"
#include "i2c_registers.h"
#include "i2c_packet.h"
#include "ble_peripheral.h" 
#include "ble_packet.h"

LOG_MODULE_REGISTER(i2c_registers);

static const struct gpio_dt_spec data_ready = 
    GPIO_DT_SPEC_GET(DT_NODELABEL(data_ready), gpios);

extern struct k_msgq i2c_msgq;

static uint8_t ring_buf_tx_data[RING_BUF_SIZE];
static uint8_t ring_buf_rx_data[RING_BUF_SIZE];

struct i2c_cmd_reg command_registers[] = {
    [I2C_REG_STATUS] = {
		.permission = REG_PERM_READ,
		.type = REG_TYPE_NORMAL,
        .data = {0x13, 0x37},
    },
    [I2C_REG_DEV_ID] = {
		.permission = REG_PERM_READ,
		.type = REG_TYPE_NORMAL,
        .data = {0xBE, 0xEF},
    },
    [I2C_REG_INT_SRC] = {
		.permission = REG_PERM_READ,
		.type = REG_TYPE_NORMAL,
        .data = {0x00, 0x00, 0x00, 0x00},
    },
    [I2C_REG_TX_BUF] = {
		.permission = REG_PERM_RW,
		.type = REG_TYPE_RINGBUF,
		.ring_buffer_mem = ring_buf_tx_data,
    },
    [I2C_REG_RX_BUF] = {
		.permission = REG_PERM_RW,
		.type = REG_TYPE_RINGBUF,
		.ring_buffer_mem = ring_buf_rx_data,
    },
    [I2C_REG_RX_NUM] = {
		.permission = REG_PERM_READ,
		.type = REG_TYPE_VIRTUAL,
    },
    [I2C_REG_BLE_ADVERTISING] = {
		.permission = REG_PERM_RW,
		.type = REG_TYPE_VIRTUAL,
    },
    [I2C_REG_BLE_CONN_PARAM] = {
		.permission = REG_PERM_RW,
		.type = REG_TYPE_VIRTUAL,
    },
    [I2C_REG_BLE_POWER] = {
		.permission = REG_PERM_RW,
		.type = REG_TYPE_VIRTUAL,
    },
};

static void init_ring_buffers(void) {
    // Initialize TX buffer
    ring_buf_init(&command_registers[I2C_REG_TX_BUF].ring_data,
                  RING_BUF_SIZE,
                  command_registers[I2C_REG_TX_BUF].ring_buffer_mem);
    
    // Initialize RX buffer
    ring_buf_init(&command_registers[I2C_REG_RX_BUF].ring_data,
                  RING_BUF_SIZE,
                  command_registers[I2C_REG_RX_BUF].ring_buffer_mem);
}

static int i2c_trigger_interrupt(enum int_types interrupt) {
	int err = gpio_pin_set_dt(&data_ready, 1);
	if (err < 0) {
		LOG_ERR("Error setting interrupt pin (err: %d)", err);
		return err;
	}

	k_msleep(CONFIG_I2C_BRIDGE_INT_HIGH_MS);

	err = gpio_pin_set_dt(&data_ready, 0);
	if (err < 0) {
		LOG_ERR("Error setting interrupt pin (err: %d)", err);
		return err;
	}

	uint32_t status_reg = sys_get_be32(command_registers[I2C_REG_INT_SRC].data);
	status_reg &= interrupt;
	sys_put_be32(status_reg, command_registers[I2C_REG_INT_SRC].data);

	return 0;
}

static int i2c_reg_status_handler(struct i2c_reg_packet *packet) {
    LOG_INF("Status register packet");
    if (packet->read) {
        memcpy(packet->plaintext, command_registers[I2C_REG_STATUS].data, DATA_SIZE_BYTES);
    }
    return 0;
}

static int i2c_reg_dev_id_handler(struct i2c_reg_packet *packet) {
    LOG_INF("Device ID packet");
    if (packet->read) {
        memcpy(packet->plaintext, command_registers[I2C_REG_DEV_ID].data, DATA_SIZE_BYTES);
    }
    return 0;
}

static int i2c_reg_dev_int_src_handler(struct i2c_reg_packet *packet) {
	LOG_INF("Interrupt source packet");
    if (packet->read) {
        memcpy(packet->plaintext, command_registers[I2C_REG_DEV_ID].data, DATA_SIZE_BYTES);
    }
	return 0;
}

static int i2c_reg_ble_advertising_handler(struct i2c_reg_packet *packet) {
    LOG_INF("Advertising packet");
    if (packet->read) {
        memcpy(packet->plaintext, command_registers[I2C_REG_BLE_ADVERTISING].data, DATA_SIZE_BYTES);
    } else {
        memcpy(command_registers[I2C_REG_BLE_ADVERTISING].data, packet->plaintext, DATA_SIZE_BYTES);
    }
    return 0;
}

static int i2c_reg_ble_connection_handler(struct i2c_reg_packet *packet) {
    LOG_INF("Connection packet");
    if (packet->read) {
        memcpy(packet->plaintext, command_registers[I2C_REG_BLE_CONN_PARAM].data, DATA_SIZE_BYTES);
    } else {
        memcpy(command_registers[I2C_REG_BLE_CONN_PARAM].data, packet->plaintext, DATA_SIZE_BYTES);
    }
    return 0;
}

static int i2c_reg_ble_power_handler(struct i2c_reg_packet *packet) {
    LOG_INF("Power packet");
    if (packet->read) {
        memcpy(packet->plaintext, command_registers[I2C_REG_BLE_POWER].data, DATA_SIZE_BYTES);
    } else {
        memcpy(command_registers[I2C_REG_BLE_POWER].data, packet->plaintext, DATA_SIZE_BYTES);
    }
    return 0;
}

static int i2c_reg_tx_buf_handler(struct i2c_reg_packet *packet) {
    LOG_INF("TX buf packet");
    
    if (packet->read) {
        // Read from TX ring buffer
        uint32_t read_size = ring_buf_get(&command_registers[I2C_REG_TX_BUF].ring_data,
                                        packet->plaintext,
                                        sizeof(packet->plaintext));
        if (read_size == 0) {
            LOG_WRN("TX buffer empty");
            return -EAGAIN;
        }
        return 0;
    } else {
        // Write to TX ring buffer
        uint32_t written = ring_buf_put(&command_registers[I2C_REG_TX_BUF].ring_data,
                                      packet->plaintext,
                                      sizeof(packet->plaintext));
        
        if (written != sizeof(packet->plaintext)) {
            LOG_WRN("TX buffer full, partial write %d bytes", written);
            return -ENOMEM;
        }

        struct ble_packet plaintext;
        memcpy(plaintext.plaintext, packet->plaintext, sizeof(packet->plaintext));
        plaintext.magic = BLE_PACKET_MAGIC;

        struct ble_enc_packet ciphertext;
        encrypt_ble_packet(&plaintext, &ciphertext);
        i2c_bridge_transmit(&ciphertext);
        
        LOG_HEXDUMP_INF(plaintext.plaintext, sizeof(plaintext.plaintext), "Plaintext: ");
        LOG_HEXDUMP_INF(ciphertext.data, sizeof(ciphertext.data), "Ciphertext: ");
        LOG_INF("Sending to BLE central...");
        return 0;
    }
}

static void update_rx_buf_size(void) {
	uint32_t ring_buf_size = ring_buf_size_get(&command_registers[I2C_REG_RX_BUF].ring_data);
	sys_put_le32(ring_buf_size, command_registers[I2C_REG_RX_NUM].data);
}

static int i2c_reg_rx_buf_handler(struct i2c_reg_packet *packet) {
    if (packet->read) {
        // Read from RX ring buffer
        uint32_t read_size = ring_buf_get(&command_registers[I2C_REG_RX_BUF].ring_data,
                                        packet->plaintext,
                                        sizeof(packet->plaintext));

		update_rx_buf_size();
        
        if (read_size == 0) {
            LOG_WRN("RX buffer empty");
            return -EAGAIN;
        }

		uint32_t status_reg = sys_get_be32(command_registers[I2C_REG_INT_SRC].data);
		status_reg |= INT_TYPE_BLE_RX;
    }
    return 0;
}

static int i2c_reg_rx_num_handler(struct i2c_reg_packet *packet) {
	LOG_INF("RX num packet");
	if (packet->read) {
		update_rx_buf_size();
        memcpy(packet->plaintext, command_registers[I2C_REG_RX_NUM].data, DATA_SIZE_BYTES);
	}
	return 0;
}

static int (*i2c_reg_handlers[])(struct i2c_reg_packet *) = {
    i2c_reg_status_handler,
    i2c_reg_dev_id_handler,
	i2c_reg_dev_int_src_handler,
    i2c_reg_tx_buf_handler,
    i2c_reg_rx_buf_handler,
	i2c_reg_rx_num_handler,
    i2c_reg_ble_advertising_handler,
    i2c_reg_ble_connection_handler,
    i2c_reg_ble_power_handler,
};

BUILD_ASSERT(ARRAY_SIZE(i2c_reg_handlers) != (I2C_REG_END - 1),
            "Number of handlers must match number of registers");

static bool is_read_command(uint8_t *data) {
    for (int i = 0; i < DATA_SIZE_BYTES; i++) {
        if (data[i] != 0) {
            return false;
        }
    }
    return true;
}

void write_rx_register(uint8_t *buf) {
    uint32_t written = ring_buf_put(&command_registers[I2C_REG_RX_BUF].ring_data,
                                  buf,
                                  DATA_SIZE_BYTES);
    
    if (written >= DATA_SIZE_BYTES) {
        LOG_WRN("RX buffer written with %d bytes, more than data packet size", written);
    }
	
	update_rx_buf_size();

	int err = i2c_trigger_interrupt(INT_TYPE_BLE_RX);
    if (err < 0) {
        LOG_ERR("Error setting interrupt pin (err: %d)", err);
    }
}

int i2c_register_handler(void) {
    LOG_INF("Beginning secure I2C -> NUS bridge");

    if (!gpio_is_ready_dt(&data_ready)) {
        LOG_ERR("Interrupt GPIO not ready.");
        return -1;
    }

    int err = gpio_pin_configure_dt(&data_ready, GPIO_OUTPUT_INACTIVE);
    if (err < 0) {
        LOG_ERR("Interrupt GPIO configuration failed (err: %d)", err);
        return -1;
    }

    // Initialize ring buffers
    init_ring_buffers();

    struct i2c_reg_packet plaintext;
    while (true) {
        k_msgq_get(&i2c_msgq, &plaintext, K_FOREVER);
        plaintext.read = is_read_command(plaintext.plaintext);
        i2c_reg_handlers[plaintext.reg](&plaintext);
        LOG_HEXDUMP_DBG(plaintext.plaintext, sizeof(plaintext.plaintext), "i2c cmd");
    }
}

#define THREAD_STACK_SIZE 2048 
#define THREAD_PRIORITY 5

K_THREAD_DEFINE(i2c_register_thread, THREAD_STACK_SIZE,
                i2c_register_handler, NULL, NULL, NULL,
                THREAD_PRIORITY, 0, 0);
