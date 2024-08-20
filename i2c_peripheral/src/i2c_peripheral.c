#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/linker/devicetree_regions.h>
#include <zephyr/device.h>
#include <zephyr/drivers/pinctrl.h>

#include <zephyr/drivers/i2c.h>
#include <nrfx_twis.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(i2c_peripheral);

#include "crypto.h"
#include "i2c_registers.h"

#if CONFIG_NRFX_TWIS1
#define I2C_S_INSTANCE 1
#elif CONFIG_NRFX_TWIS2
#define I2C_S_INSTANCE 2
#elif CONFIG_NRFX_TWIS22
#define I2C_S_INSTANCE 22
#elif CONFIG_NRFX_TWIS131
#define I2C_S_INSTANCE 131
#else
#error "TWIS instance not enabled or not supported"
#endif

#define NODE_TWIS   DT_NODELABEL(twi_peripheral)

#define TWIS_MEMORY_SECTION                                                                    
	COND_CODE_1(DT_NODE_HAS_PROP(NODE_TWIS, memory_regions),                                   \
		    (__attribute__((__section__(                                                       \
			    LINKER_DT_NODE_REGION_NAME(DT_PHANDLE(NODE_TWIS, memory_regions)))))),         \
		    ())

static const nrfx_twis_t twis = NRFX_TWIS_INSTANCE(I2C_S_INSTANCE);

#define RX_BUFFER_SIZE 256
static uint8_t i2c_rx_buffer[RX_BUFFER_SIZE] TWIS_MEMORY_SECTION;

K_MSGQ_DEFINE(i2c_msgq, sizeof(struct i2c_reg_packet), 16, 1);

enum i2c_cmds cmd_idx = I2C_REG_STATUS;
void i2c_peripheral_handler(nrfx_twis_evt_t const *p_event)
{
	struct i2c_reg_enc_packet ciphertext;
	struct i2c_reg_packet plaintext;

	switch (p_event->type) {
	case NRFX_TWIS_EVT_READ_REQ:
		LOG_INF("Read req");

		plaintext.magic = I2C_PACKET_MAGIC;
		plaintext.reg = cmd_idx;
		memcpy(plaintext.plaintext, command_registers[cmd_idx].data, DATA_SIZE_BYTES);

		encrypt_i2c_packet(&plaintext, &ciphertext);
		nrfx_twis_tx_prepare(&twis, &ciphertext.data, I2C_PACKET_SIZE_BYTES);
		break;

	case NRFX_TWIS_EVT_READ_DONE:
		LOG_INF("Read done");
		break;

	case NRFX_TWIS_EVT_WRITE_REQ:
		LOG_INF("Write req");
		memset(i2c_rx_buffer, 0, RX_BUFFER_SIZE);
		nrfx_twis_rx_prepare(&twis, i2c_rx_buffer, RX_BUFFER_SIZE);
		break;

	case NRFX_TWIS_EVT_WRITE_DONE:
		LOG_INF("Write done");
		// If the received data is in the proper amount...
		if (p_event->data.rx_amount == sizeof(struct i2c_reg_enc_packet)) {
			LOG_HEXDUMP_INF(i2c_rx_buffer, I2C_PACKET_SIZE_BYTES, "i2c rx");
			decrypt_i2c_packet(&plaintext, (struct i2c_reg_enc_packet *)i2c_rx_buffer);
			// If our magic value is decrypted correctly...
			if (plaintext.magic == I2C_PACKET_MAGIC) {
				cmd_idx = plaintext.reg;
				// If the command index is valid...
				if (cmd_idx < I2C_REG_END) {
					cmd_idx = plaintext.reg;
					k_msgq_put(&i2c_msgq, &plaintext, K_NO_WAIT);
				} else {
					LOG_ERR("Invalid command index: %d", cmd_idx);
				}
			} else {
				cmd_idx = I2C_REG_STATUS;
				LOG_ERR("Invalid I2C packet magic");
			}
		} else {
			LOG_ERR("Invalid encrypted packet length: %d", p_event->data.rx_amount);
		}
		break;

	default:
		LOG_INF("TWIS event: %d\n", p_event->type);
		break;
	}
}

static int i2c_peripheral_init(void)
{
	const nrfx_twis_config_t config = {
		.addr = {0x54, 0x00},
		.skip_gpio_cfg = true,
		.skip_psel_cfg = true,
	};
	int ret;

	ret = nrfx_twis_init(&twis, &config, i2c_peripheral_handler);
	if (ret != NRFX_SUCCESS) {
		LOG_ERR("Init failed: %d", ret);
		return -1;
	}

	PINCTRL_DT_DEFINE(NODE_TWIS);
	ret = pinctrl_apply_state(PINCTRL_DT_DEV_CONFIG_GET(NODE_TWIS), PINCTRL_STATE_DEFAULT);

	IRQ_CONNECT(DT_IRQN(NODE_TWIS), DT_IRQ(NODE_TWIS, priority),
		    NRFX_TWIS_INST_HANDLER_GET(I2C_S_INSTANCE), NULL, 0);

	nrfx_twis_enable(&twis);
	LOG_INF("Enabled TWIS");
	return 0;
}

SYS_INIT(i2c_peripheral_init, APPLICATION, 90);
