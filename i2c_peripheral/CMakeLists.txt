cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(peripheral_nus)

target_sources(app PRIVATE
        src/i2c_registers.c
		src/i2c_peripheral.c
		src/ble_peripheral.c
		../common/src/crypto.c
)

target_include_directories(app PRIVATE 
		../common/inc/
		inc/
)
