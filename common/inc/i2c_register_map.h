#ifndef I2C_REGISTER_MAP_H__
#define I2C_REGISTER_MAP_H__

enum i2c_cmds {
	I2C_REG_STATUS,
	I2C_REG_DEV_ID,
	I2C_REG_INT_SRC,
	I2C_REG_TX_BUF,
	I2C_REG_RX_BUF,
	I2C_REG_RX_NUM,
	I2C_REG_BLE_ADVERTISING,
	I2C_REG_BLE_CONN_PARAM,
	I2C_REG_BLE_POWER,
	I2C_REG_END,
};

#endif
