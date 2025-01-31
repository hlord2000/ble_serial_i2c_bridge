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
BT_UUID_ADC_VOLTAGE_READING_CHAR = "5914f304-2155-43e8-a446-10de62953d40"

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

def create_adc_command(sample_rate_ms, enable):
    # Pack the command: exactly 5 bytes
    # 4 bytes for sample_rate (uint32) + 1 byte for enable flag (uint8)
    return struct.pack('<IB', sample_rate_ms, 1 if enable else 0)

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
    print("Authentication packets sent.")

# Key for encryption
key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])

def subscribe_to_notifications(peripheral):
    def i2c_notification_callback(data):
        try:
            msg = decrypt_message(data[17:], data[0:17], key)
            print()
            print("Received I2C Bridge Notification")
            print(f"Decrypted message: {msg}")
        except Exception as e:
            print(f"Error decoding I2C notification: {e}")
            print(f"Raw data: {data.hex()}")

    def adc_notification_callback(data):
        print()
        print("Received ADC Notification")
        print(f"Raw data: {data.hex()}")

    print("Subscribing to notifications...")
    print(f"- I2C Bridge TX characteristic: {BT_UUID_I2C_BRIDGE_TX_CHAR}")
    print(f"- ADC characteristic: {BT_UUID_ADC_VOLTAGE_READING_CHAR}")
    
    peripheral.notify(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_TX_CHAR, i2c_notification_callback)
    peripheral.notify(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_ADC_VOLTAGE_READING_CHAR, adc_notification_callback)
    print("Subscribed to notifications.")

def send_adc_command(peripheral, sample_rate_ms, enable):
    try:
        command = create_adc_command(sample_rate_ms, enable)
        print()
        print("Sending ADC command")
        print(f"Sample rate: {sample_rate_ms}ms, Enable: {enable}")
        print(f"Raw command bytes: {command.hex()}")
        
        peripheral.write_request(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_ADC_VOLTAGE_READING_CHAR, command)
        print("ADC command sent successfully")
    except Exception as e:
        print(f"Error sending ADC command: {e}")

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
    print("Commands:")
    print("1. Send message (enter: msg <text>)")
    print("2. Configure ADC (enter: adc <sample_rate_ms> <enable>)")
    print("3. Quit (enter: q)")
    
    try:
        while True:
            command = input("Enter command: ").strip()
            if command.lower() == 'q':
                break
                
            parts = command.split()
            if not parts:
                continue
                
            if parts[0] == 'msg':
                message = ' '.join(parts[1:])
                try:
                    nonce, ciphertext = encrypt_message(message, key)
                    packet = create_ble_packet(ciphertext, nonce)
                    device.write_request(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_RX_CHAR, packet)
                    print()
                    print("Writing BLE message")
                    print(f"Plaintext: \r\n{message}")
                    print(f"Ciphertext: \r\n{packet}")
                except Exception as e:
                    print(f"Error sending message: {e}")
                    
            elif parts[0] == 'adc':
                if len(parts) != 3:
                    print("Usage: adc <sample_rate_ms> <enable>")
                    continue
                try:
                    sample_rate = int(parts[1])
                    enable = bool(int(parts[2]))
                    send_adc_command(device, sample_rate, enable)
                except ValueError:
                    print("Invalid parameters. Sample rate must be an integer and enable must be 0 or 1")
                except Exception as e:
                    print(f"Error configuring ADC: {e}")
            else:
                print("Unknown command")
                
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        print("Disconnecting...")
        device.disconnect()
        print("Disconnected.")

if __name__ == "__main__":
    main()
