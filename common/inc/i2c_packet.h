#ifndef I2C_PACKET_H__
#define I2C_PACKET_H__
#include <stdint.h>
#include <stdbool.h>

#define NONCE_SIZE_BYTES 16
#define DATA_SIZE_BYTES 16 
#define I2C_PACKET_SIZE_BYTES NONCE_SIZE_BYTES + DATA_SIZE_BYTES + 2

#define I2C_REG_PACKET_BYTES DATA_SIZE_BYTES + 2

#define I2C_PACKET_MAGIC 0xAA

struct __attribute__((packed)) i2c_reg_enc_packet {
	union {
		struct {
			uint8_t ciphertext[I2C_REG_PACKET_BYTES];
			uint8_t nonce[NONCE_SIZE_BYTES];
		};
		uint8_t data[I2C_PACKET_SIZE_BYTES];
	};
};

struct i2c_reg_packet {
    union {
        struct {
#if defined(CONFIG_BSIB_I2C_ENCRYPTION)
            uint8_t magic;
#endif
            uint8_t reg;
            uint8_t plaintext[DATA_SIZE_BYTES];
        };
        uint8_t data[I2C_REG_PACKET_BYTES];
    };
	bool read;
};

#endif
