#include <zephyr/kernel.h>
#include <zephyr/linker/devicetree_regions.h>
#include <zephyr/device.h>
#include <zephyr/drivers/pinctrl.h>

#include <nrfx_twis.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(twi_slave);

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

#define NODE_TWIS   DT_NODELABEL(twi_slave)

#define TWIS_MEMORY_SECTION                                                                        \
	COND_CODE_1(DT_NODE_HAS_PROP(NODE_TWIS, memory_regions),                                   \
		    (__attribute__((__section__(                                                   \
			    LINKER_DT_NODE_REGION_NAME(DT_PHANDLE(NODE_TWIS, memory_regions)))))), \
		    ())

#define TEST_DATA_SIZE 6

static uint8_t twi_slave_buffer[TEST_DATA_SIZE] TWIS_MEMORY_SECTION;

static nrfx_twis_t m_twis_inst = NRFX_TWIS_INSTANCE(I2C_S_INSTANCE);

void twis_handler(nrfx_twis_evt_t const *p_event)
{
	printk("IDK\r\n");
	switch (p_event->type) {
	case NRFX_TWIS_EVT_READ_REQ:
		nrfx_twis_tx_prepare(&m_twis_inst, twi_slave_buffer, TEST_DATA_SIZE);
		printk("TWIS event: read request\n");
		break;
	case NRFX_TWIS_EVT_READ_DONE:
		printk("TWIS event: read done\n");
		break;
	case NRFX_TWIS_EVT_WRITE_REQ:
		nrfx_twis_rx_prepare(&m_twis_inst, twi_slave_buffer, TEST_DATA_SIZE);
		printk("TWIS event: write request\n");
		break;
	case NRFX_TWIS_EVT_WRITE_DONE:
		printk("TWIS event: write done\n");
		break;
	default:
		printk("TWIS event: %d\n", p_event->type);
		break;
	}
}

int twi_slave_init(void) {
	int err;

    nrfx_twis_config_t twis_config = {
		.addr = {0x54, 0},
		.skip_gpio_cfg = true,
		.skip_psel_cfg = true,
	};

    err = nrfx_twis_init(&m_twis_inst, &twis_config, twis_handler);
	if (err < 0) {
		LOG_ERR("I2C Slave init failed err: (%d)", err);
		return err;
	}

	PINCTRL_DT_DEFINE(NODE_TWIS);
	err = pinctrl_apply_state(PINCTRL_DT_DEV_CONFIG_GET(NODE_TWIS), PINCTRL_STATE_DEFAULT);

	IRQ_CONNECT(DT_IRQN(NODE_TWIS), DT_IRQ(NODE_TWIS, priority),
		    NRFX_TWIS_INST_HANDLER_GET(I2C_S_INSTANCE), NULL, 0);

	nrfx_twis_enable(&m_twis_inst);

	return 0;
}

SYS_INIT(twi_slave_init, POST_KERNEL, 50);
