from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import json
import binascii
import random

class DynamicIVJce:
    @staticmethod
    def generate_dynamic_iv():
        return ''.join(chr(random.randint(47, 126)) for _ in range(16)).encode('utf-8')

    @staticmethod
    def encrypt(data_to_encrypt, secret_hex_key):
        try:
            # Convert hex key to bytes
            key = binascii.unhexlify(secret_hex_key)
            if len(key) not in [16, 24, 32]:
                raise ValueError("Key length must be 16, 24, or 32 bytes")

            # Generate dynamic IV
            iv = DynamicIVJce.generate_dynamic_iv()

            # Initialize cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(data_to_encrypt.encode('utf-8'), AES.block_size)
            encrypted = cipher.encrypt(padded_data)

            # Prefix IV and encode final payload
            final_output = iv + encrypted
            return base64.b64encode(final_output).decode('utf-8')
        except Exception as e:
            print("Encryption Error:", str(e))
            return None

if __name__ == "__main__":
    payload = {
        "initiateAuthGenericFundTransferAPIReq": {
            "tellerBranch": "",
            "tellerID": "",
            "transactionID": "762666283",
            "debitAccountNumber": "21495193614",
            "creditAccountNumber": "123456041",
            "remitterName": "RAHUL",
            "amount": "10000",
            "currency": "INR",
            "transactionType": "NEFT",
            "paymentDescription": "1T45541",
            "beneficiaryIFSC": "UTIB0000001",
            "beneficiaryName": "RAMESH",
            "beneficiaryAddress": "",
            "emailId":"abc@gmail.com",
            "mobileNo": "9999999999"
        }

    }

    data = json.dumps(payload)  # ✔️ convert dict to JSON string
    secret_hex_key = "76616d706c65446467654135536b959123686d706c65406488631144536b9201"

    encrypted = DynamicIVJce.encrypt(data, secret_hex_key)  # ✔️ use json string
    if encrypted:
        print("Encrypted Payload:")
        print(encrypted)