from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import base64


def encrypt_message(message, key):
    # Convert key to 256-bit key using SHA-256
    key_hash = SHA256.new(data=key.encode('utf-8')).digest()

    # Create cipher with random IV
    cipher = AES.new(key_hash, AES.MODE_CBC)

    # Pad and encrypt
    if not isinstance(message, bytes):
        message = message.encode('utf-8')

    padded_data = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    # Return both ciphertext and IV for decryption
    return ciphertext, cipher.iv


def decrypt_message(ciphertext, iv, key):
    try:
        # Convert key to 256-bit key using SHA-256
        key_hash = SHA256.new(data=key.encode('utf-8')).digest()

        # Recreate cipher with same IV
        cipher = AES.new(key_hash, AES.MODE_CBC, iv)

        # Decrypt and unpad
        padded_data = cipher.decrypt(ciphertext)
        data = unpad(padded_data, AES.block_size)

        # Convert to string
        return data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


# Test with a simple message
message = "2"
key = "secret_key"

# Encrypt
ciphertext, iv = encrypt_message(message, key)
print(f"Original: {message}")
print(f"Encrypted (hex): {ciphertext}")

# Decrypt
decrypted = decrypt_message(ciphertext, iv, key)
print(f"Decrypted: {decrypted}")