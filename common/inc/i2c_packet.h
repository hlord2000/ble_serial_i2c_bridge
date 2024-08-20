#ifndef I2C_PACKET_H__
#define I2C_PACKET_H__
#include <stdint.h>

#define NONCE_SIZE_BYTES 8
#define DATA_SIZE_BYTES 8
#define PACKET_SIZE_BYTES NONCE_SIZE_BYTES + DATA_SIZE_BYTES

#define I2C_PACKET_MAGIC 0xAA

struct __attribute__((packed)) encrypted_packet {
	uint8_t ciphertext[DATA_SIZE_BYTES];
	uint8_t nonce[NONCE_SIZE_BYTES];
};

struct decrypted_packet {
    union {
        struct {
            uint8_t magic;
            uint8_t reg;
            uint8_t data[DATA_SIZE_BYTES - 2];
        };
        uint8_t plaintext[DATA_SIZE_BYTES];
    };
};


#endif
