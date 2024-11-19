#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/shell/shell.h>
#include <string.h>
#include <stdlib.h>

#include "i2c_packet.h"
#include "i2c_register_map.h"
#include "crypto.h"

LOG_MODULE_REGISTER(main);

#define MAX_MESSAGE_LENGTH 16


const struct i2c_dt_spec i2c_dev = I2C_DT_SPEC_GET(DT_NODELABEL(peripheral));

static const struct gpio_dt_spec data_ready = GPIO_DT_SPEC_GET(DT_NODELABEL(data_ready), gpios);

static int i2c_bridge_read(struct i2c_reg_packet *plaintext, enum i2c_cmds cmd) {
	int result;

	plaintext->magic = I2C_PACKET_MAGIC;
	plaintext->reg = cmd;
	memset(plaintext->plaintext, 0, sizeof(plaintext->plaintext));

#if defined(CONFIG_BSIB_I2C_ENCRYPTION)
    struct i2c_reg_enc_packet ciphertext = {0};
	result = encrypt_i2c_packet(plaintext, &ciphertext);
	if (result < 0) {
		LOG_ERR("I2C encrypt failed (err: %d)", result);
		return -1;
	}

	uint8_t results_buf[I2C_PACKET_SIZE_BYTES];

    result = i2c_write_read_dt(
                &i2c_dev, 
                ciphertext.data, 
                sizeof(struct i2c_reg_enc_packet), 
                results_buf, 
				I2C_PACKET_SIZE_BYTES
    );
	if (result < 0) {
		LOG_ERR("I2C write/read failed (err: %d)", result);
		return -1;
	}
	LOG_HEXDUMP_INF(results_buf, I2C_PACKET_SIZE_BYTES, "Ciphertext:");

    result = decrypt_i2c_packet(plaintext, (struct i2c_reg_enc_packet *)results_buf);
	if (result < 0) {
		LOG_ERR("I2C decrypt failed (err: %d)", result);
		return -1;
	}
#else

	uint8_t results_buf[I2C_REG_PACKET_BYTES];
    result = i2c_write_read_dt(
                &i2c_dev, 
                plaintext->data, 
                sizeof(struct i2c_reg_packet), 
                results_buf, 
				I2C_REG_PACKET_BYTES 
    );
	if (result < 0) {
		LOG_ERR("Failed to send unencrypted I2C packet (err: %d)", result);
		return -1;
	}

	memcpy(plaintext, results_buf, I2C_REG_PACKET_BYTES);
#endif
	return 0;
}

static void read_work_handler(struct k_work *work)
{
	struct i2c_reg_packet plaintext;
	LOG_INF("I2C Packet");
    i2c_bridge_read(&plaintext, I2C_REG_RX_BUF);
	LOG_HEXDUMP_INF(plaintext.plaintext, sizeof(plaintext.plaintext), "Plaintext: ");
}

K_WORK_DEFINE(read_work, read_work_handler);

static struct gpio_callback data_ready_cb_data;

void data_ready_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins) {
	k_work_submit(&read_work);
}

#if defined(CONFIG_BSIB_I2C_ENCRYPTION)
static int cmd_encrypt_send(const struct shell *shell, size_t argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        shell_error(shell, "Usage: encrypt_send <register> [data]");
        return -EINVAL;
    }

    struct i2c_reg_packet plaintext = {0};
    struct i2c_reg_enc_packet ciphertext = {0};

    plaintext.magic = I2C_PACKET_MAGIC;
    plaintext.reg = (uint8_t)strtol(argv[1], NULL, 0);

    if (argc == 3) {
        size_t message_len = strlen(argv[2]);
        if (message_len > MAX_MESSAGE_LENGTH - 1) {
            shell_error(shell, "Data too long. Max length is %d", MAX_MESSAGE_LENGTH - 1);
            return -EINVAL;
        }
        strncpy(plaintext.plaintext, argv[2], message_len);
    }

    int result = encrypt_i2c_packet(&plaintext, &ciphertext);
    if (result < 0) {
        shell_error(shell, "Encryption failed");
        return result;
    }

    uint8_t results_buf[I2C_PACKET_SIZE_BYTES];

    result = i2c_write_read_dt(
                &i2c_dev, 
                ciphertext.data, 
                sizeof(struct i2c_reg_enc_packet), 
                results_buf, 
				I2C_PACKET_SIZE_BYTES
    );

    if (result < 0) {
        shell_error(shell, "Failed to send encrypted message over I2C");
        return result;
    }

    result = decrypt_i2c_packet(&plaintext, (struct i2c_reg_enc_packet *)results_buf);
    shell_print(shell, "Encrypted message sent successfully");
    return 0;
}
#endif

static int cmd_write_tx_reg(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: write_tx_reg <data>");
        return -EINVAL;
    }

	int result;
    struct i2c_reg_packet plaintext = {0};
#if defined(CONFIG_BSIB_I2C_ENCRYPTION)
    struct i2c_reg_enc_packet ciphertext = {0};
#endif

    plaintext.magic = I2C_PACKET_MAGIC;
    plaintext.reg = I2C_REG_TX_BUF;

    size_t message_len = strlen(argv[1]);
    if (message_len > MAX_MESSAGE_LENGTH - 1) {
        shell_error(shell, "Data too long. Max length is %d", MAX_MESSAGE_LENGTH - 1);
        return -EINVAL;
    }
    strncpy(plaintext.plaintext, argv[1], message_len);

#if defined(CONFIG_BSIB_I2C_ENCRYPTION)
    result = encrypt_i2c_packet(&plaintext, &ciphertext);
    if (result < 0) {
        shell_error(shell, "Encryption failed");
        return result;
    }

    result = i2c_write_dt(&i2c_dev, ciphertext.data, sizeof(struct i2c_reg_enc_packet));
    if (result < 0) {
        shell_error(shell, "Failed to write to TX register");
        return result;
    }
#endif
    result = i2c_write_dt(&i2c_dev, plaintext.data, sizeof(struct i2c_reg_packet));
    if (result < 0) {
        shell_error(shell, "Failed to write to unencrypted TX register");
        return result;
    }

    shell_print(shell, "Successfully wrote to TX register");
	shell_print(shell, "Plaintext: ");
	shell_hexdump(shell, plaintext.plaintext, sizeof(plaintext.plaintext));
#if defined(CONFIG_BSIB_I2C_ENCRYPTION)
	shell_print(shell, "Ciphertext: ");
	shell_hexdump(shell, ciphertext.data, sizeof(ciphertext.data));
#endif
    return 0;
}

static int cmd_read_rx_reg(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 1) {
        shell_error(shell, "Usage: read_rx_reg");
        return -EINVAL;
    }

    shell_print(shell, "Successfully read from RX register");
    struct i2c_reg_packet plaintext = {0};
    int result = i2c_bridge_read(&plaintext, I2C_REG_RX_BUF);
    if (result < 0) {
        shell_error(shell, "Failed to read from RX register");
        return result;
    }
	shell_print(shell, "Plaintext: ");
	shell_hexdump(shell, plaintext.plaintext, sizeof(plaintext.plaintext));
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(i2c_bridge_cmds,
    SHELL_CMD(write_tx, NULL, "Write to TX register", cmd_write_tx_reg),
    SHELL_CMD(read_rx, NULL, "Read from RX register", cmd_read_rx_reg),
#if defined(CONFIG_BSIB_I2C_ENCRYPTION)
    SHELL_CMD(encrypt_send, NULL, "Encrypt and send a message over I2C", cmd_encrypt_send),
#endif
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(i2c_bridge, &i2c_bridge_cmds, "I2C Bridge commands", NULL);

int main(void)
{
    if (!device_is_ready(i2c_dev.bus)) {
        LOG_ERR("I2C NOT READY");
        return -EIO;
    }

	if (!gpio_is_ready_dt(&data_ready)) {
		LOG_ERR("Data ready line not ready %s", data_ready.port->name);
		return 0;
	}

	int err = gpio_pin_configure_dt(&data_ready, GPIO_INPUT);
	if (err < 0) {
		LOG_ERR("Error: %d, failed to configure %s pin %d", err,
		  		data_ready.port->name, data_ready.pin);
	}

	err = gpio_pin_interrupt_configure_dt(&data_ready, GPIO_INT_EDGE_TO_ACTIVE);
	if (err < 0) {
		LOG_ERR("Failed (err: %d) to configure interrupt on %s pin %d", err,
		  		data_ready.port->name, data_ready.pin);
	}

	gpio_init_callback(&data_ready_cb_data, data_ready_cb, BIT(data_ready.pin));
	gpio_add_callback(data_ready.port, &data_ready_cb_data);
    return 0;
}
