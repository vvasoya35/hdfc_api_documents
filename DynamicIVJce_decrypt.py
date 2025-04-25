
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import binascii

class DynamicIVJce:
    @staticmethod
    def decrypt(encrypted_base64, secret_hex_key):
        try:
            # Convert hex key to bytes
            key = binascii.unhexlify(secret_hex_key)
            if len(key) not in [16, 24, 32]:
                raise ValueError("Key length must be 16, 24, or 32 bytes")

            # Decode base64 to get IV + encrypted data
            combined_data = base64.b64decode(encrypted_base64)

            # Extract IV and encrypted payload
            iv = combined_data[:16]
            encrypted_data = combined_data[16:]

            # Initialize cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            return decrypted.decode('utf-8')
        except Exception as e:
            print("Decryption Error:", str(e))
            return None

if __name__ == "__main__":
    # Sample Base64 encoded encrypted payload (update with your actual encrypted string)
    encrypted_payload = "cTRHR1U4UkFMZnQ5PDVvPB85lX7k98ER9UW4/sXnzOq5EYksUefbX8b+QZMLqXZatW/O8Sk8k2P3o1iKDudZocYvWtLdQASMwhwminKC5M2fQgZ+1tWYoYbvTN7TYO/o6E8vmgSw0wRhm+jT/e5o4HWEyx/MB0w0fX7yurYqEj3u/VsVZU4q9EyxNLka7ETWS7MO9M3YiEfEGEMxQeK04CMAHYX5OYYy2Fz0kvumueXJF2T1CB/WuYXsXRk3PH9bK/SFz7so6aUHL2EKad3JP+XQT0hKXjrrC+3FfmvpL4Qxt6zxSuorxW16WKkexh1irmX+1Q6RCtb6ju7GYtMJrMMsQ+gQPJDr3oitmOUdn5xcFAgXY3KFyWhDn0rnsMNvUvVck2iKbJ/Rih6M9vnZTA=="

    # Sample AES-256 Key (hex, 32 bytes when decoded)
    secret_hex_key = "76616d706c65446467654135536b959123686d706c65406488631144536b9201"

    # Decrypt using AES-256 CBC with extracted IV
    decrypted = DynamicIVJce.decrypt(encrypted_payload, secret_hex_key)
    if decrypted:
        print("Decrypted Payload:")
        print(decrypted)
