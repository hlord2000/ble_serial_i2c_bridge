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
#include "i2c_peripheral.h"

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

#define TWIS_MEMORY_SECTION                                                                        \
	COND_CODE_1(DT_NODE_HAS_PROP(NODE_TWIS, memory_regions),                                   \
		    (__attribute__((__section__(                                                   \
			    LINKER_DT_NODE_REGION_NAME(DT_PHANDLE(NODE_TWIS, memory_regions)))))), \
		    ())

static const nrfx_twis_t twis = NRFX_TWIS_INSTANCE(I2C_S_INSTANCE);

#define RX_BUFFER_SIZE  128
static uint8_t i2c_rx_buffer[RX_BUFFER_SIZE] TWIS_MEMORY_SECTION;

K_MSGQ_DEFINE(i2c_msgq, sizeof(struct i2c_packet), 16, 1);

struct i2c_cmd_reg command_registers[I2C_REG_END] = {
	{ /* I2C_REG_STATUS */
		.data = {},
		.read = true,
		.write = true,
	},
	{ /* I2C_REG_DEV_ID */
		.data = {},
		.read = true,
		.write = false,
	}, 
	{ /* I2C_REG_ADV_ENABLE */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_TX_BUF */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_TX_BUF_LEN */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_RX_BUF */
		.data = {},
		.read = true,
		.write = true,
	}, 
	{ /* I2C_REG_RX_BUF_LEN */
		.data = {},
		.read = true,
		.write = true,
	}, 
};

enum i2c_cmds cmd_idx = I2C_REG_STATUS;
void i2c_peripheral_handler(nrfx_twis_evt_t const *p_event)
{
	switch (p_event->type) {
	case NRFX_TWIS_EVT_READ_REQ:
		LOG_INF("Read req\r\n");
		uint8_t cipherdata[16];
		encrypt_ctr_aes(NULL, command_registers[cmd_idx].data, 16, cipherdata, 16);
		nrfx_twis_tx_prepare(&twis, cipherdata, 16);
		break;
	case NRFX_TWIS_EVT_READ_DONE:
		LOG_INF("Read done\r\n");
		break;
	case NRFX_TWIS_EVT_WRITE_REQ:
		memset(i2c_rx_buffer, 0, RX_BUFFER_SIZE);
		nrfx_twis_rx_prepare(&twis, i2c_rx_buffer, RX_BUFFER_SIZE);
		break;
	case NRFX_TWIS_EVT_WRITE_DONE:
		struct i2c_packet *packet = (struct i2c_packet *)i2c_rx_buffer;
		uint8_t plaintext[8];
		decrypt_ctr_aes(packet->nonce, packet->ciphertext, sizeof(packet->ciphertext), plaintext, sizeof(plaintext));
		k_msgq_put(&i2c_msgq, i2c_rx_buffer, K_NO_WAIT);
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
		LOG_ERR("Init failed: %d\r\n", ret);
		return -1;
	}

	PINCTRL_DT_DEFINE(NODE_TWIS);
	ret = pinctrl_apply_state(PINCTRL_DT_DEV_CONFIG_GET(NODE_TWIS), PINCTRL_STATE_DEFAULT);

	IRQ_CONNECT(DT_IRQN(NODE_TWIS), DT_IRQ(NODE_TWIS, priority),
		    NRFX_TWIS_INST_HANDLER_GET(I2C_S_INSTANCE), NULL, 0);

	nrfx_twis_enable(&twis);
	LOG_INF("Enabled TWIS\r\n");
	return 0;
}

SYS_INIT(i2c_peripheral_init, APPLICATION, 90);
