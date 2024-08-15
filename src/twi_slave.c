#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/pinctrl.h>

#include <nrfx_twis.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(twi_slave);

#define TWIS_INST_IDX 30

//const struct pinctrl_dev_config *twi_slave_pcfg = PINCTRL_DT_DEV_CONFIG_GET(DT_NODELABEL(i2c30));

// No more portable way to do this instance num, so far as I can surmize. Please refer to the
// zephyr/drivers/i2c/i2c_nrfx_twim.c for what may be a better method.
static nrfx_twis_t m_twis_inst = NRFX_TWIS_INSTANCE(TWIS_INST_IDX);


static void twis_handler(nrfx_twis_evt_t const * p_event)
{
    /* Variable to store register number sent in the last TX. */
    static uint8_t reg_buff[255];

    switch (p_event->type)
    {
        case NRFX_TWIS_EVT_WRITE_REQ:
            nrfx_twis_rx_prepare(&m_twis_inst, &reg_buff, sizeof(reg_buff));
            break;

        case NRFX_TWIS_EVT_READ_REQ:
            nrfx_twis_tx_prepare(&m_twis_inst, NULL, NULL);
            break;

        default:
            break;
    }
}

int twi_slave_init(void) {
	int err;

	IRQ_CONNECT(DT_IRQN(DT_NODELABEL(twi_slave)),
			 	DT_IRQ(DT_NODELABEL(twi_slave), priority),
				nrfx_isr, 0, 0);

	uint32_t scl_pin;
	uint32_t sda_pin;

    nrfx_twis_config_t twis_config = {
		.addr = {0x69, 0x42},
//		.scl_pin = DT_ACROBATICS!!!,
//		.sda_pin = DT_ACROBATICS!!!,
		.scl_pull = NRF_GPIO_PIN_PULLUP,
		.sda_pull = NRF_GPIO_PIN_PULLUP,
		.interrupt_priority = NRFX_TWIS_DEFAULT_CONFIG_IRQ_PRIORITY,
	};

    err = nrfx_twis_init(&m_twis_inst, &twis_config, twis_handler);
	if (err < 0) {
		LOG_ERR("I2C Slave init failed err: (%d)", err);
		return err;
	}

	nrfx_twis_enable(&m_twis_inst);

	return 0;
}

SYS_INIT(twi_slave_init, POST_KERNEL, 90);
