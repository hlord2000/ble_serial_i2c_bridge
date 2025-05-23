#ifndef BLE_PERIPHERAL_H__
#define BLE_PERIPHERAL_H__
#include <ble_packet.h>

int i2c_bridge_transmit(struct ble_enc_packet *packet);

int adc_voltage_transmit(int32_t millivolts);

#endif
