#ifndef BLE_PACKET_H__
#define BLE_PACKET_H__
#include <stdint.h>
#include <stdbool.h>

#define NONCE_SIZE_BYTES 16
#define DATA_SIZE_BYTES 16 
#define BLE_PACKET_SIZE_BYTES NONCE_SIZE_BYTES + DATA_SIZE_BYTES + 1

#define BLE_PACKET_BYTES DATA_SIZE_BYTES + 1

#define BLE_PACKET_MAGIC 0xBB

struct __attribute__((packed)) ble_enc_packet {
	union {
		struct {
			uint8_t ciphertext[BLE_PACKET_BYTES];
			uint8_t nonce[NONCE_SIZE_BYTES];
		};
		uint8_t data[BLE_PACKET_SIZE_BYTES];
	};
};

struct __attribute__((packed)) ble_packet {
    union {
        struct {
            uint8_t magic;
            uint8_t plaintext[DATA_SIZE_BYTES];
        };
        uint8_t data[BLE_PACKET_BYTES];
    };
};

#endif
