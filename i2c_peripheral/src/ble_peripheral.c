#include <zephyr/kernel.h>
#include <zephyr/bluetooth/gatt.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ble_peripheral);

#define BT_UUID_I2C_BRIDGE_SRV_VAL \
	BT_UUID_128_ENCODE(0x5914f300, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)
#define BT_UUID_I2C_BRIDGE_RX_CHAR_VAL \
	BT_UUID_128_ENCODE(0x5914f301, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)
#define BT_UUID_I2C_BRIDGE_TX_CHAR_VAL \
	BT_UUID_128_ENCODE(0x5914f302, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)
#define BT_UUID_I2C_BRIDGE_AUTH_CHAR_VAL \
	BT_UUID_128_ENCODE(0x5914f303, 0x2155, 0x43e8, 0xa446, 0x10de62953d40)

#define BT_UUID_I2C_BRIDGE_SERVICE   BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_SRV_VAL)
#define BT_UUID_I2C_BRIDGE_TX_CHAR   BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_TX_CHAR_VAL)
#define BT_UUID_I2C_BRIDGE_RX_CHAR   BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_RX_CHAR_VAL)
#define BT_UUID_I2C_BRIDGE_AUTH_CHAR BT_UUID_DECLARE_128(BT_UUID_I2C_BRIDGE_AUTH_CHAR_VAL)

static void i2c_bridge_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value) {
	bool notif_enabled = (value == BT_GATT_CCC_NOTIFY);
	LOG_INF("Notficiations enabled");
}

ssize_t i2c_bridge_bt_chr_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
	const void *buf, uint16_t len, uint16_t offset, uint8_t flags) {
	return 0;
}

BT_GATT_SERVICE_DEFINE(i2c_bridge_svc,								   
	BT_GATT_PRIMARY_SERVICE(BT_UUID_I2C_BRIDGE_SERVICE),						   
	BT_GATT_CHARACTERISTIC(BT_UUID_I2C_BRIDGE_TX_CHAR,						   
		BT_GATT_CHRC_NOTIFY,								   
		BT_GATT_PERM_READ_LESC,								   
		NULL, NULL, NULL),								   
	BT_GATT_CCC(i2c_bridge_ccc_cfg_changed,							   
		BT_GATT_PERM_READ_LESC | BT_GATT_PERM_WRITE_LESC),					   
	BT_GATT_CHARACTERISTIC(BT_UUID_I2C_BRIDGE_RX_CHAR,						   
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,						   
		BT_GATT_PERM_WRITE_LESC,								   
		NULL, i2c_bridge_bt_chr_write, NULL),							   
	BT_GATT_CHARACTERISTIC(BT_UUID_I2C_BRIDGE_AUTH_CHAR,
		BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_WRITE,
		BT_GATT_PERM_READ_LESC | BT_GATT_PERM_WRITE_LESC,
		NULL, NULL, NULL),
	BT_GATT_CCC(i2c_bridge_ccc_cfg_changed,							   
		BT_GATT_PERM_READ_LESC | BT_GATT_PERM_WRITE_LESC),					   
);												   
