#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/bluetooth.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ble_peripheral);

#include "crypto.h"
#include "shared_keys.h"
#include "i2c_registers.h"
#include "ble_packet.h"
#include "ble_peripheral.h"
#include "adc.h"

struct bt_conn *current_connection = NULL;

#define BLE_EVT_CONNECTED BIT(0)
#define BLE_EVT_AUTHENTICATED BIT(1)

#define BLE_EVT_I2C_BRIDGE_NOTIFS_ENABLED BIT(2)
#define BLE_EVT_ADC_NOTIFS_ENABLED BIT(3)

K_EVENT_DEFINE(ble_conn_state_events);

#if defined(CONFIG_I2C_BRIDGE_AUTH_ENABLE)
static void disconnect_work_handler(struct k_work *work) {
	LOG_INF("Disconnecting from unauthenticated central");
    bt_conn_disconnect(current_connection, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

K_WORK_DEFINE(disconnect_work, disconnect_work_handler);

static void auth_timeout_expiry(struct k_timer *timer) {
	k_work_submit(&disconnect_work);
	k_event_clear(&ble_conn_state_events, BLE_EVT_AUTHENTICATED);
}
#endif

#define BT_UUID_I2C_BRIDGE_SRV_VAL \
	BT_UUID_128_ENCODE(0x5914f300, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)
#define BT_UUID_I2C_BRIDGE_RX_CHAR_VAL \
	BT_UUID_128_ENCODE(0x5914f301, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)
#define BT_UUID_I2C_BRIDGE_TX_CHAR_VAL \
	BT_UUID_128_ENCODE(0x5914f302, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)
#if defined(CONFIG_I2C_BRIDGE_AUTH_ENABLE)
#define BT_UUID_I2C_BRIDGE_AUTH_CHAR_VAL \
	BT_UUID_128_ENCODE(0x5914f303, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)
#endif
#define BT_UUID_ADC_VOLTAGE_READING_VAL \
	BT_UUID_128_ENCODE(0x5914f304, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)

#define BT_UUID_I2C_BRIDGE_SERVICE   BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_SRV_VAL)
#define BT_UUID_I2C_BRIDGE_TX_CHAR   BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_TX_CHAR_VAL)
#define BT_UUID_I2C_BRIDGE_RX_CHAR   BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_RX_CHAR_VAL)
#define BT_UUID_ADC_VOLTAGE_READING  BT_UUID_DECLARE_128(BT_UUID_ADC_VOLTAGE_READING_VAL)

#if defined(CONFIG_I2C_BRIDGE_AUTH_ENABLE)
#define BT_UUID_I2C_BRIDGE_AUTH_CHAR BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_AUTH_CHAR_VAL)
K_TIMER_DEFINE(auth_timeout, auth_timeout_expiry, NULL);
#endif

static void i2c_bridge_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value) {
	if (value == BT_GATT_CCC_NOTIFY) {
		k_event_set_masked(&ble_conn_state_events, BLE_EVT_I2C_BRIDGE_NOTIFS_ENABLED, BLE_EVT_I2C_BRIDGE_NOTIFS_ENABLED);
		LOG_INF("I2C bridge BLE central notifications enabled");
	} else {
		k_event_clear(&ble_conn_state_events, BLE_EVT_I2C_BRIDGE_NOTIFS_ENABLED);
	}
}

K_MSGQ_DEFINE(ble_msgq, sizeof(struct ble_enc_packet), 16, 1);

static void ble_decrypt_work_handler(struct k_work *work) {
	int err;
	struct ble_enc_packet ciphertext;
	k_msgq_get(&ble_msgq, &ciphertext, K_MSEC(100));

	struct ble_packet plaintext = {0};
	
	err = decrypt_ble_packet(&plaintext, &ciphertext);
	if (err < 0) {
		LOG_ERR("Decrypt failed (err: %d)", err);
		return;
	}

	if (plaintext.magic == BLE_PACKET_MAGIC) {
		write_rx_register(plaintext.plaintext);
	}
	LOG_INF("BLE Write Packet");
	LOG_HEXDUMP_INF(ciphertext.data, sizeof(ciphertext.data), "Ciphertext:");
	LOG_HEXDUMP_INF(plaintext.plaintext, sizeof(plaintext.plaintext), "Plaintext:");
}

K_WORK_DEFINE(ble_decrypt_work, ble_decrypt_work_handler);

ssize_t i2c_bridge_bt_chr_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
	const void *buf, uint16_t len, uint16_t offset, uint8_t flags) {
	if (len != sizeof(struct ble_enc_packet)) {
		LOG_ERR("Invalid packet size");
		return -1;
	}
	LOG_INF("%d", ble_conn_state_events.events);
	if (k_event_test(&ble_conn_state_events, BLE_EVT_AUTHENTICATED)) {
		LOG_INF("Got write");
		k_msgq_put(&ble_msgq, (struct ble_enc_packet *)buf, K_NO_WAIT);
		k_work_submit(&ble_decrypt_work);
		return len;
	} else {
		LOG_ERR("Not authenticated");
		return -1;
	}
}

#if defined(CONFIG_I2C_BRIDGE_AUTH_ENABLE)
static ssize_t i2c_bridge_write_auth(struct bt_conn *conn, 
									 const struct bt_gatt_attr *attr,
									 const void *buf,
									 uint16_t len, uint16_t offset, uint8_t flags) {
	int err;

	LOG_INF("Auth packet");
	LOG_HEXDUMP_INF(buf, len, "Ciphertext: ");
	if (len != sizeof(struct ble_enc_packet)) {
		LOG_ERR("Invalid auth char length");
		return -1;
	}

	struct ble_packet plaintext = {0};
	err = decrypt_ble_packet(&plaintext, (struct ble_enc_packet *)buf);
	if (err < 0) {
		LOG_ERR("Decrypt failed (err: %d)", err);
		return -1;
	}
	LOG_HEXDUMP_INF(plaintext.plaintext, sizeof(plaintext.plaintext), "Plaintext: ");

	if (plaintext.magic == BLE_PACKET_MAGIC) {
		if (memcmp(plaintext.plaintext, ble_auth_message, sizeof(ble_auth_message))) {
			return -1;
		} else {
			LOG_INF("Auth success");
			k_timer_stop(&auth_timeout);
			k_event_set_masked(&ble_conn_state_events, BLE_EVT_AUTHENTICATED, BLE_EVT_AUTHENTICATED);
			return len;
		}
	} else {
		return -1;
	}
}
#endif

static ssize_t adc_voltage_write_config(struct bt_conn *conn, 
									 const struct bt_gatt_attr *attr,
									 const void *buf,
									 uint16_t len, uint16_t offset, uint8_t flags) {
	if (len != sizeof(struct adc_config)) {
		LOG_ERR("Invalid adc config length: %d", len);
		return -1;
	}

	LOG_HEXDUMP_INF(buf, len, "adc config");
	
	const struct adc_config *config = (const struct adc_config *)buf;

	LOG_INF("Sampling enabled: %b", config->sampling_enabled);
	LOG_INF("Sampling rate ms: %d", config->sampling_rate_ms);
	
	if (config->sampling_enabled) {
		k_timer_start(&adc_timer, K_MSEC(config->sampling_rate_ms), K_MSEC(config->sampling_rate_ms));
		k_event_set_masked(&adc_events, ADC_SAMPLING_ENABLED, ADC_SAMPLING_ENABLED);
	} else {
		k_timer_stop(&adc_timer);
		k_event_clear(&adc_events, ADC_SAMPLING_ENABLED);
	}
	
	return len;	
}

static void adc_voltage_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value) {
	if (value == BT_GATT_CCC_NOTIFY) {
		k_event_set_masked(&ble_conn_state_events, BLE_EVT_ADC_NOTIFS_ENABLED, BLE_EVT_ADC_NOTIFS_ENABLED);
		LOG_INF("ADC central notifications enabled");
	} else {
		LOG_INF("ADC CCC val: %d", value);
		k_event_clear(&ble_conn_state_events, BLE_EVT_ADC_NOTIFS_ENABLED);
	}
}

BT_GATT_SERVICE_DEFINE(i2c_bridge_svc,								   
	BT_GATT_PRIMARY_SERVICE(BT_UUID_I2C_BRIDGE_SERVICE),						   
	BT_GATT_CHARACTERISTIC(BT_UUID_I2C_BRIDGE_TX_CHAR,						   
		BT_GATT_CHRC_NOTIFY,								   
		BT_GATT_PERM_READ,								   
		NULL, NULL, NULL),								   
	BT_GATT_CCC(i2c_bridge_ccc_cfg_changed,							   
		BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),					   
	BT_GATT_CHARACTERISTIC(BT_UUID_I2C_BRIDGE_RX_CHAR,						   
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,						   
		BT_GATT_PERM_WRITE,								   
		NULL, i2c_bridge_bt_chr_write, NULL),							   
#if defined(CONFIG_I2C_BRIDGE_AUTH_ENABLE)
	BT_GATT_CHARACTERISTIC(BT_UUID_I2C_BRIDGE_AUTH_CHAR,
		BT_GATT_CHRC_WRITE,
		BT_GATT_PERM_WRITE,
		NULL, i2c_bridge_write_auth, NULL),
#endif
	BT_GATT_CHARACTERISTIC(BT_UUID_ADC_VOLTAGE_READING,						   
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,								   
		BT_GATT_PERM_WRITE,								   
		NULL, adc_voltage_write_config, NULL),								   
	BT_GATT_CCC(adc_voltage_ccc_cfg_changed,							   
		BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),					   
);												   

#define DEVICE_NAME		CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN		(sizeof(DEVICE_NAME) - 1)

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

static const struct bt_data sd[] = {
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_I2C_BRIDGE_SRV_VAL),
};

static void start_advertising(void) {
	int err;

	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_2, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
	if (err) {
		LOG_ERR("Failed to start advertising: %d", err);
		return;
	}
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err) {
		LOG_ERR("Failed to connect to %s (%u)", addr, err);
		bt_conn_unref(current_connection);
		current_connection = NULL;
		return;
	}

	k_event_set_masked(&ble_conn_state_events, BLE_EVT_CONNECTED, BLE_EVT_CONNECTED);
	LOG_INF("Connected %s", addr);

#if defined(CONFIG_I2C_BRIDGE_AUTH_ENABLE)
	k_timer_start(&auth_timeout, K_SECONDS(CONFIG_I2C_BRIDGE_AUTH_TIMEOUT), K_NO_WAIT);
#endif
	current_connection = conn;

	err = bt_le_adv_stop();
	if (err) {
		LOG_INF("Failed to stop advertising");
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	bt_conn_unref(current_connection);
	current_connection = NULL;

	k_timer_stop(&adc_timer);
	k_event_clear(&ble_conn_state_events, BLE_EVT_CONNECTED);
	k_event_clear(&ble_conn_state_events, BLE_EVT_AUTHENTICATED);
	LOG_INF("Disconnected from %s (reason 0x%02x)", addr, reason);

	start_advertising();
}

static void security_changed(struct bt_conn *conn, bt_security_t level,
			     enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!err) {
		LOG_INF("Security changed: %s level %u", addr, level);
	} else {
		LOG_ERR("Security failed: %s level %u err %d", addr, level,
		       err);
	}
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed,
};

int i2c_bridge_transmit(struct ble_enc_packet *packet) {
	int err;

	LOG_INF("Testing if BLE_EVT_AUTHENTICATED | BLE_EVT_I2C_BRIDGE_NOTIFS_ENABLED set: %d, %d", BLE_EVT_AUTHENTICATED | BLE_EVT_I2C_BRIDGE_NOTIFS_ENABLED, ble_conn_state_events.events);
	if (k_event_test(&ble_conn_state_events, BLE_EVT_AUTHENTICATED | BLE_EVT_I2C_BRIDGE_NOTIFS_ENABLED)) {
		err = bt_gatt_notify_uuid(current_connection, 
								  BT_UUID_I2C_BRIDGE_TX_CHAR,
								  attr_i2c_bridge_svc,
								  packet->data,
								  sizeof(struct ble_enc_packet)
		);
	} else {
		LOG_ERR("Notifications for I2C bridge not enabled");
		return -1;
	}
	return err;
}

int adc_voltage_transmit(int32_t millivolts) {
	int err;

	uint8_t array[4] = sys_uint32_to_array((uint32_t)millivolts);

	err = bt_gatt_notify_uuid(current_connection, 
							  BT_UUID_ADC_VOLTAGE_READING,
							  attr_i2c_bridge_svc,
							  array,
							  sizeof(array)
	);

	return err;
}

int ble_init(void)
{
	int err;

	if (IS_ENABLED(CONFIG_SETTINGS)) {
		settings_load();
	}

	err = bt_enable(NULL);
	if (err) {
		LOG_ERR("Failed to enable bluetooth: %d", err);
		return err;
	}

	start_advertising();

	LOG_INF("Initialization complete");

	return 0;
}
SYS_INIT(ble_init, APPLICATION, 99);

/* Thread stack size */
#define STACK_SIZE 1024
/* Thread priority */
#define THREAD_PRIORITY 7

/* Thread function */
void ble_event_monitor(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    while (1) {
        uint32_t current_events = ble_conn_state_events.events;
        LOG_INF("BLE connection state events: 0x%08x", current_events);
        k_sleep(K_SECONDS(1));
    }
}

/* Define the thread */
K_THREAD_DEFINE(ble_monitor_id, STACK_SIZE,
                ble_event_monitor, NULL, NULL, NULL,
                THREAD_PRIORITY, 0, 0);
