import simplepyble
import binascii
import time
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct

# Constants
NONCE_SIZE_BYTES = 16
DATA_SIZE_BYTES = 16
BLE_PACKET_SIZE_BYTES = NONCE_SIZE_BYTES + DATA_SIZE_BYTES + 1
BLE_PACKET_BYTES = DATA_SIZE_BYTES + 1
BLE_PACKET_MAGIC = 0xBB
DEVICE_NAME = "Zephyr"

# UUID definitions
BT_UUID_I2C_BRIDGE_SVC = "5914f300-2155-43e8-a446-10de62953d40"
BT_UUID_I2C_BRIDGE_RX_CHAR = "5914f301-2155-43e8-a446-10de62953d40"
BT_UUID_I2C_BRIDGE_TX_CHAR = "5914f302-2155-43e8-a446-10de62953d40"
BT_UUID_I2C_BRIDGE_AUTH_CHAR = "5914f303-2155-43e8-a446-10de62953d40"

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def encrypt_message(message, key):
    nonce = os.urandom(NONCE_SIZE_BYTES)
    ctr = Counter.new(128, initial_value=int_of_string(nonce))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    padded_message = struct.pack('B16s', BLE_PACKET_MAGIC, message.encode()[:16])
    ciphertext = cipher.encrypt(padded_message)
    return nonce, ciphertext

def decrypt_message(nonce, ciphertext, key):
    ctr = Counter.new(128, initial_value=int_of_string(nonce))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    decrypted = cipher.decrypt(ciphertext)
    magic, message = struct.unpack('B16s', decrypted)
    if magic != BLE_PACKET_MAGIC:
        raise ValueError("Invalid magic number")
    return message.rstrip(b'\x00').decode()

def create_ble_packet(ciphertext, nonce):
    packet = struct.pack(f"{BLE_PACKET_BYTES}s{NONCE_SIZE_BYTES}s",
                         ciphertext, nonce)
    return packet

def scan_and_select_adapter():
    adapters = simplepyble.Adapter.get_adapters()
    if not adapters:
        print("No Bluetooth adapters found.")
        return None

    print("Available Bluetooth adapters:")
    for i, adapter in enumerate(adapters):
        print(f"{i}: {adapter.identifier()} [{adapter.address()}]")

    return adapters[0]

def scan_for_devices(adapter):
    print("Scanning for devices...")
    adapter.set_callback_on_scan_start(lambda: print("Scan started."))
    adapter.set_callback_on_scan_stop(lambda: print("Scan complete."))
    adapter.set_callback_on_scan_found(lambda peripheral: print(f"Found {peripheral.identifier()} [{peripheral.address()}]") if peripheral.identifier() == DEVICE_NAME else None)
    adapter.scan_for(2500)
    return adapter.scan_get_results()

def select_device(peripherals):
    dev_idx = 0
    print("\nAvailable devices:")
    for i, peripheral in enumerate(peripherals):
        print(f"{i}: {peripheral.identifier()} [{peripheral.address()}]")
        if (peripheral.identifier() == DEVICE_NAME):
            dev_idx = i

    return peripherals[dev_idx]

def connect_to_device(peripheral):
    print(f"Connecting to: {peripheral.identifier()} [{peripheral.address()}]")
    peripheral.connect()
    print("Successfully connected.")
    
    print("Discovered services:")
    for service in peripheral.services():
        print(f"Service UUID: {service.uuid()}")
        for characteristic in service.characteristics():
            print(f"  Characteristic UUID: {characteristic.uuid()}")
            print(f"  UUID type {type(characteristic.uuid())}")

def authenticate_device(peripheral, key):
    message = "NORDIC"
    nonce, ciphertext = encrypt_message(message, key)
    packet = create_ble_packet(ciphertext, nonce)

    print("Authenticating device...")
    try:
        peripheral.write_request(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_AUTH_CHAR, packet)
    except:
        print("exception on write")
    print("Authentication packet sent.")

# Key for encryption
key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])

def subscribe_to_notifications(peripheral):
    def notification_callback(data):
        msg = decrypt_message(data[17:], data[0:17], key)
        print()
        print("Recevied BLE Notification")
        print(f"Ciphertext: \r\n{data}")
        print(f"Plaintext: \r\n{msg}")

    print("Subscribing to notifications...")
    peripheral.notify(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_TX_CHAR, notification_callback)
    print("Subscribed to notifications.")

def main():
    adapter = scan_and_select_adapter()
    if not adapter:
        return

    peripherals = scan_for_devices(adapter)
    if not peripherals:
        print("No devices found.")
        return

    device = select_device(peripherals)
    connect_to_device(device)

    authenticate_device(device, key)
    subscribe_to_notifications(device)

    print("\nDevice is ready for communication.")
    print("You can now send data to the RX characteristic.")
    
    try:
        while True:
            message = input("Enter message to send (or 'q' to quit): ")
            if message.lower() == 'q':
                break
            try:
                nonce, ciphertext = encrypt_message(message, key)
                packet = create_ble_packet(ciphertext, nonce)
                device.write_request(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_RX_CHAR, packet)
                print()
                print("Writing BLE message")
                print(f"Plaintext: \r\n{message}")
                print(f"Ciphertext: \r\n{packet}")
            except:
                pass
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        print("Disconnecting...")
        device.disconnect()
        print("Disconnected.")

if __name__ == "__main__":
    main()
