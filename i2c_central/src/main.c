#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/shell/shell.h>
#include <string.h>
#include <stdlib.h>

#include "i2c_packet.h"
#include "i2c_register_map.h"
#include "crypto.h"

LOG_MODULE_REGISTER(main);

const struct i2c_dt_spec i2c_dev = I2C_DT_SPEC_GET(DT_NODELABEL(peripheral));

#define MAX_MESSAGE_LENGTH 16

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

SHELL_CMD_REGISTER(encrypt_send, NULL, "Encrypt and send a message over I2C", cmd_encrypt_send);

int main(void)
{
    if (!device_is_ready(i2c_dev.bus)) {
        LOG_ERR("I2C NOT READY");
        return -EIO;
    }

    return 0;
}
