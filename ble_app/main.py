from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

def encrypt_aes_ctr(plaintext, key, nonce):
    # Convert key list to bytes
    key_bytes = bytes(key)
    
    # Ensure the key is 16, 24, or 32 bytes long (128, 192, or 256 bits)
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long")
    
    # Ensure the nonce is 8 bytes long (64 bits)
    if len(nonce) != 8:
        raise ValueError("Nonce must be 8 bytes long")

    # Create a new Counter object
    ctr = Counter.new(64, prefix=nonce, initial_value=0)

    # Create AES cipher object in CTR mode
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))

    return ciphertext

def format_output(nonce, ciphertext):
    combined = nonce + ciphertext
    return ', '.join(f'0x{byte:02X}' for byte in combined)

# Example usage
key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
nonce = os.urandom(8)  # Generate a random 8-byte nonce
plaintext = "This is a secret message."

encrypted = encrypt_aes_ctr(plaintext, key, nonce)
formatted_output = format_output(nonce, encrypted)
print(f"Nonce + Encrypted: {formatted_output}")
