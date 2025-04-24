import simplepyble
import binascii
import time
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct
import sys

# Constants
NONCE_SIZE_BYTES = 16
DATA_SIZE_BYTES = 16
# BLE_PACKET_BYTES = DATA_SIZE_BYTES + 1 # 17 bytes (Magic + Data)
BLE_PACKET_BYTES = DATA_SIZE_BYTES + 1 # Corrected constant name for clarity
ENCRYPTED_DATA_PAYLOAD_SIZE = BLE_PACKET_BYTES # 17 bytes (Magic + Encrypted Data)
# Expected total encrypted packet size: Encrypted Data Payload + Nonce
EXPECTED_ENCRYPTED_PACKET_SIZE = ENCRYPTED_DATA_PAYLOAD_SIZE + NONCE_SIZE_BYTES # 17 + 16 = 33 bytes

BLE_PACKET_MAGIC = 0xBB
DEVICE_NAME = "Zephyr" # Make sure this matches your device's advertised name

# UUID definitions
# Ensure these UUIDs are correct for your Zephyr application
BT_UUID_I2C_BRIDGE_SVC = "5914f300-2155-43e8-a446-10de62953d40"
BT_UUID_I2C_BRIDGE_RX_CHAR = "5914f301-2155-43e8-a446-10de62953d40" # Write (client -> server)
BT_UUID_I2C_BRIDGE_TX_CHAR = "5914f302-2155-43e8-a446-10de62953d40" # Notify (server -> client)
BT_UUID_I2C_BRIDGE_AUTH_CHAR = "5914f303-2155-43e8-a446-10de62953d40" # Write (client -> server)
BT_UUID_ADC_VOLTAGE_READING_CHAR = "5914f304-2155-43e8-a446-10de62953d40" # Notify/Read/Write (Notify for readings, Write for config)

def log(message):
    """Helper function for consistent logging output."""
    # print(f"[LOG] {message}", file=sys.stderr) # Use stderr so it doesn't mix with input()
    # For simplicity, let's print to stdout again, but with the tag
    print(f"[LOG] {message}")


def int_of_string(s):
    """Converts a bytes object to an integer."""
    if not s:
        return 0 # Handle empty bytes gracefully
    return int(binascii.hexlify(s), 16)

def encrypt_message(message, key):
    """Encrypts a message using AES-CTR."""
    log(f"Encrypting message: '{message[:30]}...' (len: {len(message)})") # Log message start
    nonce = os.urandom(NONCE_SIZE_BYTES)
    log(f"Generated nonce: {nonce.hex()} (len: {len(nonce)})")

    # The message needs to be padded/truncated to exactly DATA_SIZE_BYTES (16)
    # and then prepended with the magic byte, total 17 bytes for encryption.
    padded_message = message.encode('utf-8')
    if len(padded_message) > DATA_SIZE_BYTES:
        log(f"Warning: Message too long ({len(padded_message)} bytes), truncating to {DATA_SIZE_BYTES}.")
        padded_message = padded_message[:DATA_SIZE_BYTES]
    elif len(padded_message) < DATA_SIZE_BYTES:
         log(f"Padding message from {len(padded_message)} to {DATA_SIZE_BYTES} bytes with nulls.")
         padded_message = padded_message.ljust(DATA_SIZE_BYTES, b'\x00')

    # Create the 17-byte block to encrypt: Magic + Padded Data
    block_to_encrypt = struct.pack(f'B{DATA_SIZE_BYTES}s', BLE_PACKET_MAGIC, padded_message)
    log(f"Block to encrypt: {block_to_encrypt.hex()} (len: {len(block_to_encrypt)})") # Should be 17 bytes

    try:
        # Initialize AES in CTR mode
        ctr = Counter.new(128, initial_value=int_of_string(nonce))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        log("AES cipher initialized in CTR mode.")

        # Encrypt the 17-byte block
        ciphertext = cipher.encrypt(block_to_encrypt)
        log(f"Encryption successful. Ciphertext len: {len(ciphertext)}") # Should be 17 bytes

    except Exception as e:
        log(f"Error during encryption: {e}")
        raise # Re-raise the exception

    return nonce, ciphertext # Return 16-byte nonce and 17-byte ciphertext

def decrypt_message(nonce, ciphertext, key):
    """Decrypts a message using AES-CTR."""
    log("-> decrypt_message called")
    log(f"  Nonce length: {len(nonce)}")
    log(f"  Ciphertext length: {len(ciphertext)}")
    log(f"  Key length: {len(key)}")

    # Basic length checks before calling crypto functions
    if len(nonce) != NONCE_SIZE_BYTES:
        log(f"  ERROR: decrypt_message received nonce of incorrect size. Expected {NONCE_SIZE_BYTES}, got {len(nonce)}")
        raise ValueError("Invalid nonce size for decryption")
    if len(ciphertext) != ENCRYPTED_DATA_PAYLOAD_SIZE: # Expecting 17 bytes ciphertext
         log(f"  ERROR: decrypt_message received ciphertext of incorrect size. Expected {ENCRYPTED_DATA_PAYLOAD_SIZE}, got {len(ciphertext)}")
         raise ValueError("Invalid ciphertext size for decryption")
    if len(key) not in [16, 24, 32]: # AES key lengths
         log(f"  ERROR: decrypt_message received key of incorrect size. Expected 16, 24, or 32, got {len(key)}")
         raise ValueError("Invalid key size for decryption")


    try:
        # Initialize AES in CTR mode
        initial_value = int_of_string(nonce)
        ctr = Counter.new(128, initial_value=initial_value)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        log("  AES cipher initialized in CTR mode.")

        # Decrypt the ciphertext (should be 17 bytes)
        decrypted = cipher.decrypt(ciphertext)
        log(f"  Decryption successful. Decrypted data length: {len(decrypted)}") # Should be 17 bytes

        # Unpack the decrypted data: 1 byte magic + 16 bytes padded message
        if len(decrypted) != ENCRYPTED_DATA_PAYLOAD_SIZE:
             log(f"  ERROR: Decrypted data has unexpected length! Expected {ENCRYPTED_DATA_PAYLOAD_SIZE}, got {len(decrypted)}")
             raise ValueError("Decrypted data has incorrect length")

        magic, message = struct.unpack(f'B{DATA_SIZE_BYTES}s', decrypted) # Unpack 1 byte and 16 bytes
        log(f"  Unpacked magic: {hex(magic)}, message part length: {len(message)}") # Magic should be BLE_PACKET_MAGIC, message len 16

        if magic != BLE_PACKET_MAGIC:
            log(f"  ERROR: Invalid magic number received! Expected {hex(BLE_PACKET_MAGIC)}, got {hex(magic)}")
            # Log raw decrypted data here for diagnosis if magic is wrong
            log(f"  Raw decrypted data (hex): {decrypted.hex()}")
            raise ValueError("Invalid magic number")

        log("<- decrypt_message successful")
        # Decode message, strip potential null padding added by struct.pack('16s')
        return message.rstrip(b'\x00').decode('utf-8')

    except struct.error as se:
        log(f"  ERROR during struct.unpack: {se}")
        # Log decrypted data state if unpack fails
        log(f"  Decrypted data length: {len(decrypted) if 'decrypted' in locals() else 'N/A'}")
        if 'decrypted' in locals():
            log(f"  Decrypted data (hex): {decrypted.hex()}")
        raise ValueError(f"Failed to unpack decrypted data: {se}") from se # Re-raise as ValueError
    except Exception as e:
        log(f"  ERROR during decryption setup or AES operation: {e}")
        raise # Re-raise the original exception


def create_ble_packet(ciphertext, nonce):
    """Combines ciphertext and nonce into a single BLE packet."""
    log("-> create_ble_packet called")
    log(f"  Ciphertext length: {len(ciphertext)}") # Should be 17
    log(f"  Nonce length: {len(nonce)}")         # Should be 16

    if len(ciphertext) != ENCRYPTED_DATA_PAYLOAD_SIZE:
         log(f"  ERROR: create_ble_packet received ciphertext of incorrect size. Expected {ENCRYPTED_DATA_PAYLOAD_SIZE}, got {len(ciphertext)}")
         raise ValueError("Invalid ciphertext size for packet creation")
    if len(nonce) != NONCE_SIZE_BYTES:
         log(f"  ERROR: create_ble_packet received nonce of incorrect size. Expected {NONCE_SIZE_BYTES}, got {len(nonce)}")
         raise ValueError("Invalid nonce size for packet creation")


    # Pack ciphertext (17 bytes) followed by nonce (16 bytes)
    packet = struct.pack(f"{ENCRYPTED_DATA_PAYLOAD_SIZE}s{NONCE_SIZE_BYTES}s",
                         ciphertext, nonce)
    log(f"  Created packet len: {len(packet)}") # Should be 33 bytes
    log(f"<- create_ble_packet successful")
    return packet

def create_adc_command(sample_rate_ms, enable):
    """Creates a command packet for the ADC characteristic."""
    log(f"-> create_adc_command called (rate: {sample_rate_ms}, enable: {enable})")
    # Pack the command: exactly 5 bytes (4 bytes uint32 sample_rate + 1 byte uint8 enable)
    command = struct.pack('<IB', sample_rate_ms, 1 if enable else 0)
    log(f"  Created command bytes: {command.hex()} (len: {len(command)})")
    log("<- create_adc_command successful")
    return command

def scan_and_select_adapter():
    """Scans for and selects a Bluetooth adapter."""
    log("Scanning for Bluetooth adapters...")
    adapters = simplepyble.Adapter.get_adapters()
    if not adapters:
        log("No Bluetooth adapters found.")
        return None

    log("Available Bluetooth adapters:")
    for i, adapter in enumerate(adapters):
        log(f"{i}: {adapter.identifier()} [{adapter.address()}]")

    # Assuming the first adapter is the desired one, or add logic to select
    if adapters:
        log(f"Selecting adapter 0: {adapters[0].identifier()} [{adapters[0].address()}]")
        return adapters[0]
    return None


def scan_for_devices(adapter):
    """Scans for peripherals and returns the list."""
    log("Scanning for devices...")
    adapter.set_callback_on_scan_start(lambda: log("Scan started."))
    adapter.set_callback_on_scan_stop(lambda: log("Scan complete."))
    # Log found devices, highlighting the target device
    adapter.set_callback_on_scan_found(
        lambda peripheral: log(f"Found {peripheral.identifier()} [{peripheral.address()}]" +
                               (f" <-- Target '{DEVICE_NAME}'" if peripheral.identifier() == DEVICE_NAME else ""))
    )
    # Scan for a sufficient duration
    scan_duration_ms = 5000 # Increased scan time slightly
    log(f"Scanning for {scan_duration_ms} ms...")
    adapter.scan_for(scan_duration_ms)
    peripherals = adapter.scan_get_results()
    log(f"Scan results: Found {len(peripherals)} devices.")
    return peripherals

def select_device(peripherals):
    """Selects the target device by name."""
    log(f"Selecting target device '{DEVICE_NAME}'...")
    target_device = None
    for peripheral in peripherals:
        if peripheral.identifier() == DEVICE_NAME:
            target_device = peripheral
            log(f"Found target device: {target_device.identifier()} [{target_device.address()}]")
            break

    if not target_device:
        log(f"ERROR: Target device '{DEVICE_NAME}' not found in scan results.")
        return None

    # If multiple devices match the name, this picks the first one found.
    return target_device

def connect_to_device(peripheral):
    """Connects to the selected peripheral."""
    log(f"Connecting to: {peripheral.identifier()} [{peripheral.address()}]")
    try:
        peripheral.connect()
        log("Successfully connected.")

        log("Discovering services and characteristics...")
        services = peripheral.services()
        log(f"Discovered {len(services)} services:")
        for service in services:
            log(f"  Service UUID: {service.uuid()}")
            characteristics = service.characteristics()
            log(f"    {len(characteristics)} characteristics:")
            for characteristic in characteristics:
                log(f"      Characteristic UUID: {characteristic.uuid()}")
                # Removed the line logging characteristic.properties()
                log(f"      UUID type {type(characteristic.uuid())}")
        log("Service discovery complete.")

    except Exception as e:
        log(f"ERROR: Failed to connect to device: {e}")
        raise # Re-raise to be caught in main

def authenticate_device(peripheral, key):
    """Authenticates with the device by sending an encrypted message."""
    message = "NORDIC" # This message must match what the peripheral expects
    log(f"Authenticating device with message: '{message}'...")
    try:
        nonce, ciphertext = encrypt_message(message, key)
        packet_to_send = create_ble_packet(ciphertext, nonce)

        log(f"Sending authentication packet (len: {len(packet_to_send)} bytes)...")
        log(f"Packet hex: {packet_to_send.hex()}")

        peripheral.write_request(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_AUTH_CHAR, packet_to_send)
        log("Authentication packet sent successfully.")
        time.sleep(0.5) # Give device a moment to process if needed

    except Exception as e:
        log(f"ERROR: Failed during authentication: {e}")
        # Decide if this is critical. For this script, let's assume it is.
        raise # Re-raise to be caught in main

# Key for encryption - MUST be 16 bytes (128 bits) for AES-128
key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
if len(key) != 16:
     log(f"ERROR: Encryption key must be 16 bytes (128 bits)! Current key is {len(key)} bytes.")
     sys.exit(1)


def subscribe_to_notifications(peripheral):
    """Subscribes to notification characteristics."""

    def i2c_notification_callback(data):
        # !!! PRIMARY FOCUS FOR SEGFAULT DEBUGGING !!!
        log("\n--- Received I2C Bridge Notification ---")
        log(f"Raw data length: {len(data)} bytes")
        log(f"Raw data (hex): {data.hex()}") # Log raw data hex for debugging

        # Expected structure: 17 bytes ciphertext + 16 bytes nonce = 33 bytes
        expected_len = EXPECTED_ENCRYPTED_PACKET_SIZE # 33 bytes
        ciphertext_len = ENCRYPTED_DATA_PAYLOAD_SIZE # 17 bytes
        nonce_len = NONCE_SIZE_BYTES                 # 16 bytes

        if len(data) != expected_len:
             log(f"WARNING: Received I2C data has unexpected length! Expected {expected_len}, got {len(data)}")
             # Log partial data if possible to see what was actually sent
             if len(data) > 0:
                  log(f"  Partial data hex: {data[:min(len(data), 64)].hex()}...") # Log first 64 bytes
             log("Skipping decryption due to incorrect data length.")
             log("--- End I2C Bridge Notification ---")
             return # Crucially, return early if data is wrong size

        try:
            # Slices should only happen if length is correct (33 bytes)
            # Slice 0:17 should give 17 bytes (ciphertext)
            # Slice 17: should give 16 bytes (nonce)
            ciphertext_slice = data[:ciphertext_len]
            nonce_slice = data[ciphertext_len:]

            log(f"Attempting decryption with:")
            log(f"  Ciphertext slice length: {len(ciphertext_slice)}") # Should be 17
            log(f"  Nonce slice length: {len(nonce_slice)}")         # Should be 16
            # Log slices' hex for debugging if lengths are correct but decryption fails
            # log(f"  Ciphertext slice (hex): {ciphertext_slice.hex()}")
            # log(f"  Nonce slice (hex): {nonce_slice.hex()}")

            # Call decrypt_message (which has its own detailed logging and checks)
            msg = decrypt_message(nonce_slice, ciphertext_slice, key)

            # If decryption succeeded
            log("Decryption successful.")
            log(f"Decrypted message: '{msg}'") # Use quotes to see leading/trailing whitespace

        except ValueError as ve: # Specific exception for Invalid magic number or size errors from decrypt_message
            log(f"Error decoding I2C notification - ValueError: {ve}")
            # The decrypt_message function logs details before re-raising ValueErrors
        except Exception as e: # Catch any other exceptions during slicing or decryption
            log(f"Error decoding I2C notification - General Exception: {e}")
            log(f"Raw data length: {len(data)} bytes")
            log(f"Raw data (hex): {data.hex()}") # Log raw data again on exception
        finally:
             log("--- End I2C Bridge Notification ---")


    def adc_notification_callback(data):
        log("\n--- Received ADC Notification ---")
        log(f"Raw data length: {len(data)} bytes")
        log(f"Raw data (hex): {data.hex()}") # Log raw data hex

        # You can add parsing logic here based on your ADC data format
        # Example: If ADC sends a little-endian 32-bit float (4 bytes)
        # if len(data) >= 4:
        #     try:
        #         voltage = struct.unpack('<f', data[:4])[0]
        #         log(f"Parsed voltage: {voltage:.4f}V")
        #     except Exception as e:
        #         log(f"Could not parse ADC data as float: {e}")
        # else:
        #      log("ADC data too short to parse as float.")

        log("--- End ADC Notification ---")


    log("Subscribing to notifications...")
    log(f"- I2C Bridge TX characteristic: {BT_UUID_I2C_BRIDGE_TX_CHAR}")
    log(f"- ADC characteristic: {BT_UUID_ADC_VOLTAGE_READING_CHAR}")

    try:
        # Subscribe to I2C TX notifications
        log(f"Attempting to subscribe to {BT_UUID_I2C_BRIDGE_TX_CHAR}...")
        peripheral.notify(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_TX_CHAR, i2c_notification_callback)
        log(f"Successfully subscribed to {BT_UUID_I2C_BRIDGE_TX_CHAR}.")

        # Subscribe to ADC notifications
        log(f"Attempting to subscribe to {BT_UUID_ADC_VOLTAGE_READING_CHAR}...")
        peripheral.notify(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_ADC_VOLTAGE_READING_CHAR, adc_notification_callback)
        log(f"Successfully subscribed to {BT_UUID_ADC_VOLTAGE_READING_CHAR}.")

        log("All subscriptions attempted.")

    except Exception as e:
        log(f"ERROR: Failed to subscribe to one or more characteristics: {e}")
        # Decide if failure to subscribe is critical
        raise # Re-raise

def send_i2c_message(peripheral, message, key):
    """Encrypts and sends an I2C bridge message."""
    log("\nSending I2C Bridge message...")
    log(f"Original message: '{message}'")
    try:
        nonce, ciphertext = encrypt_message(message, key)
        packet = create_ble_packet(ciphertext, nonce)

        log(f"Writing I2C BLE packet (len: {len(packet)} bytes) to {BT_UUID_I2C_BRIDGE_RX_CHAR}...")
        log(f"Packet hex: {packet.hex()}")

        peripheral.write_request(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_I2C_BRIDGE_RX_CHAR, packet)
        log("I2C BLE message sent successfully.")
        time.sleep(0.1) # Short delay after writing

    except Exception as e:
        log(f"ERROR sending I2C message: {e}")

def send_adc_command(peripheral, sample_rate_ms, enable):
    """Sends an ADC configuration command."""
    log("\nSending ADC command...")
    log(f"Sample rate: {sample_rate_ms}ms, Enable: {enable}")
    try:
        command = create_adc_command(sample_rate_ms, enable)
        log(f"Writing ADC command (len: {len(command)} bytes) to {BT_UUID_ADC_VOLTAGE_READING_CHAR}...")
        log(f"Command hex: {command.hex()}")

        # Note: Writing to the *same* characteristic that you subscribe to for notifications
        # is a common pattern (e.g., write config, get notifications).
        peripheral.write_request(BT_UUID_I2C_BRIDGE_SVC, BT_UUID_ADC_VOLTAGE_READING_CHAR, command)
        log("ADC command sent successfully.")
        time.sleep(0.1) # Short delay after writing

    except Exception as e:
        log(f"ERROR sending ADC command: {e}")

def main():
    peripheral = None # Initialize peripheral to None
    try:
        adapter = scan_and_select_adapter()
        if not adapter:
            log("Exiting: No adapter found.")
            return

        peripherals = scan_for_devices(adapter)
        if not peripherals:
            log("Exiting: No devices found during scan.")
            return

        # Automatically select the target device by name
        peripheral = select_device(peripherals)
        if not peripheral:
            log(f"Exiting: Target device '{DEVICE_NAME}' not found.")
            return

        connect_to_device(peripheral)

        # Wait briefly for services to be fully discovered/cached
        time.sleep(1)

        # Authentication is usually required first
        authenticate_device(peripheral, key)

        # Then subscribe to notifications you expect *from* the device
        subscribe_to_notifications(peripheral)

        log("\n--- Device is ready for communication ---")
        log("Commands:")
        log("  msg <text>                     : Send encrypted I2C bridge message")
        log("  adc <sample_rate_ms> <0|1>     : Configure ADC sampling (rate_ms, enable)")
        log("  q                              : Quit")
        log("----------------------------------------")

        while peripheral.is_connected():
            try:
                command_line = input("Enter command: ").strip()
                if not command_line:
                    continue

                parts = command_line.split()
                if not parts:
                    continue

                command = parts[0].lower()

                if command == 'q':
                    log("Quit command received.")
                    break

                elif command == 'msg':
                    if len(parts) < 2:
                        log("Usage: msg <text>")
                        continue
                    message_text = ' '.join(parts[1:])
                    send_i2c_message(peripheral, message_text, key)

                elif command == 'adc':
                    if len(parts) != 3:
                        log("Usage: adc <sample_rate_ms> <enable (0 or 1)>")
                        continue
                    try:
                        sample_rate = int(parts[1])
                        enable_val = int(parts[2])
                        if enable_val not in [0, 1]:
                             log("Invalid enable value. Must be 0 or 1.")
                             continue
                        enable = bool(enable_val)
                        send_adc_command(peripheral, sample_rate, enable)
                    except ValueError:
                        log("Invalid parameters. Sample rate must be an integer and enable must be 0 or 1.")
                    except Exception as e:
                        log(f"Error processing ADC command: {e}")

                else:
                    log(f"Unknown command: {command}")

            except EOFError: # Handle Ctrl+D
                 log("\nEOF received, quitting.")
                 break
            except KeyboardInterrupt:
                log("\nKeyboard interrupt received.")
                break
            except Exception as e:
                log(f"An unexpected error occurred in command loop: {e}")
                # Decide if this error should break the loop or just report

        # Loop ended, initiate disconnect

    except Exception as e: # Catching a broader exception type
        log(f"An error occurred during setup or main execution: {e}")
    finally:
        # Ensure disconnection happens even if errors occurred
        if peripheral and peripheral.is_connected():
            log("Disconnecting from peripheral...")
            try:
                peripheral.disconnect()
                log("Disconnected.")
            except Exception as e:
                log(f"Error during disconnection: {e}")
        else:
            log("Peripheral not connected, no disconnection needed.")
        log("Script finished.")


if __name__ == "__main__":
    main()
