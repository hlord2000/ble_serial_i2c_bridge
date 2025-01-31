#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/adc.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>
#include <zephyr/init.h>

#include "adc.h"

K_EVENT_DEFINE(adc_events);

LOG_MODULE_REGISTER(adc_driver, LOG_LEVEL_INF);

#if !DT_NODE_EXISTS(DT_PATH(zephyr_user)) || \
    !DT_NODE_HAS_PROP(DT_PATH(zephyr_user), io_channels)
#error "No suitable devicetree overlay specified"
#endif

#define DT_SPEC_AND_COMMA(node_id, prop, idx) \
    ADC_DT_SPEC_GET_BY_IDX(node_id, idx),

#define ADC_DEFAULT_SAMPLING_INTERVAL_MS 1000

static const struct adc_dt_spec adc_channels[] = {
    DT_FOREACH_PROP_ELEM(DT_PATH(zephyr_user), io_channels,
                 DT_SPEC_AND_COMMA)
};

static uint32_t sample_count;
static uint32_t sampling_interval_ms = ADC_DEFAULT_SAMPLING_INTERVAL_MS;
static uint16_t adc_buffer;
static struct adc_sequence adc_sequence;

/* Forward declaration of handlers */
static void adc_work_handler(struct k_work *work);
static void adc_timer_expiry(struct k_timer *timer);

/* Static definitions of timer and work item */
K_TIMER_DEFINE(adc_timer, adc_timer_expiry, NULL);
K_WORK_DEFINE(adc_work, adc_work_handler);

/* Forward declaration of the voltage transmission function */
int adc_voltage_transmit(int32_t millivolts);

void adc_set_sampling_interval(uint32_t interval_ms)
{
    if (interval_ms == 0) {
        LOG_WRN("Invalid sampling interval, using default");
        interval_ms = ADC_DEFAULT_SAMPLING_INTERVAL_MS;
    }
    
    sampling_interval_ms = interval_ms;
    k_timer_start(&adc_timer, K_MSEC(sampling_interval_ms), 
                 K_MSEC(sampling_interval_ms));
    
    LOG_INF("Sampling interval set to %u ms", sampling_interval_ms);
}

uint32_t adc_get_sampling_interval(void)
{
    return sampling_interval_ms;
}

static void adc_work_handler(struct k_work *work)
{
    int err;
    LOG_INF("ADC reading[%u]:", sample_count++);

    for (size_t i = 0U; i < ARRAY_SIZE(adc_channels); i++) {
        int32_t val_mv;
        
        LOG_INF("Sampling %s, channel %d", 
                adc_channels[i].dev->name,
                adc_channels[i].channel_id);

        err = adc_read_dt(&adc_channels[i], &adc_sequence);
        if (err < 0) {
            LOG_ERR("Could not read ADC (%d)", err);
            continue;
        }

        if (adc_channels[i].channel_cfg.differential) {
            val_mv = (int32_t)((int16_t)adc_buffer);
        } else {
            val_mv = (int32_t)adc_buffer;
        }

        err = adc_raw_to_millivolts_dt(&adc_channels[i], &val_mv);
        if (err < 0) {
            LOG_WRN("Value in mV not available (%d)", err);
        } else {
            LOG_INF("Channel %d value: %"PRId32" mV", 
                    adc_channels[i].channel_id, val_mv);
            
            err = adc_voltage_transmit(val_mv);
            if (err < 0) {
                LOG_ERR("Failed to transmit voltage value (%d)", err);
            }
        }
    }
}

static void adc_timer_expiry(struct k_timer *timer)
{
    k_work_submit(&adc_work);
}

static int adc_init(void)
{
    int err;

    LOG_INF("Initializing ADC driver");

    /* Initialize sequence once */
    adc_sequence.buffer = &adc_buffer;
    adc_sequence.buffer_size = sizeof(adc_buffer);

    /* Configure channels and sequences */
    for (size_t i = 0U; i < ARRAY_SIZE(adc_channels); i++) {
        if (!adc_is_ready_dt(&adc_channels[i])) {
            LOG_ERR("ADC controller device %s not ready", 
                    adc_channels[i].dev->name);
            return -ENODEV;
        }

        err = adc_channel_setup_dt(&adc_channels[i]);
        if (err < 0) {
            LOG_ERR("Could not setup channel #%d (%d)", i, err);
            return err;
        }

        err = adc_sequence_init_dt(&adc_channels[i], &adc_sequence);
        if (err < 0) {
            LOG_ERR("Could not init sequence for channel #%d (%d)", i, err);
            return err;
        }

        LOG_DBG("ADC channel %d configured successfully", i);
    }

    LOG_INF("ADC driver initialized successfully");
    return 0;
}

SYS_INIT(adc_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
