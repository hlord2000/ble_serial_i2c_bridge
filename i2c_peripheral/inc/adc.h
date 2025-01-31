#ifndef ADC_H__
#define ADC_H__
#include <zephyr/kernel.h>

#define ADC_SAMPLING_ENABLED BIT(0) 

extern struct k_event adc_events;

extern struct k_timer adc_timer;

struct adc_config {
	uint32_t sampling_rate_ms;
	bool sampling_enabled;
} __packed;

#endif
