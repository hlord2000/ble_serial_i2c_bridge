#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/shell/shell.h>
#include <string.h>

#include "crypto.h"

LOG_MODULE_REGISTER(main);

const struct i2c_dt_spec i2c_dev = I2C_DT_SPEC_GET(DT_NODELABEL(peripheral));

#define MAX_MESSAGE_LENGTH 8 

static int cmd_encrypt_send(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: encrypt_send <message>");
        return -EINVAL;
    }

    uint8_t plaintext[MAX_MESSAGE_LENGTH];
    uint8_t ciphertext[MAX_MESSAGE_LENGTH + 8];
    size_t message_len = strlen(argv[1]);

    if (message_len > MAX_MESSAGE_LENGTH - 1) {
        shell_error(shell, "Message too long. Max length is %d", MAX_MESSAGE_LENGTH - 1);
        return -EINVAL;
    }

    strncpy(plaintext, argv[1], message_len);
    plaintext[message_len] = '\0';

	uint8_t iv_buf[8] = {0};

    int result = encrypt_ctr_aes(iv_buf, plaintext, message_len, ciphertext + 8, MAX_MESSAGE_LENGTH);
    if (result < 0) {
        shell_error(shell, "Encryption failed");
        return result;
    }

    if (!device_is_ready(i2c_dev.bus)) {
        shell_error(shell, "I2C NOT READY");
        return -EIO;
    }

    result = i2c_write_dt(&i2c_dev, ciphertext, message_len);
    if (result < 0) {
        shell_error(shell, "Failed to send encrypted message over I2C");
        return result;
    }

    shell_print(shell, "Encrypted message sent successfully");
    return 0;
}

SHELL_CMD_REGISTER(encrypt_send, NULL, "Encrypt and send a message over I2C", cmd_encrypt_send);

int main(void)
{
    if (!device_is_ready(i2c_dev.bus)) {
        LOG_ERR("I2C NOT READY");
        return -EIO;
    }

    return 0;
}
