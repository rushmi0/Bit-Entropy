import hashlib
import base58
import ecdsa
import os

for i in range(3):
    entropy = os.urandom(1)
    entropy = int.from_bytes(entropy, byteorder='big')
    print('[Entropy]\n\t└──',entropy, type(entropy))

    entropy = str(entropy)
    # The entropy value provided
    # entropy = "38766413131554711441609171699933889075768828643520792654963350783865875608609"

    # 1. Use the entropy value as the seed input to a cryptographic hash function such as SHA-256
    private_key = hashlib.sha256(entropy.encode()).hexdigest()

    # 2. Add a prefix "80" to the private key to indicate it's a private key in the format used by the Bitcoin
    private_key = "80" + private_key

    # 3. Perform a double SHA-256 hash on the private key to generate a checksum
    checksum = hashlib.sha256(hashlib.sha256(private_key.encode()).digest()).hexdigest()[:8]

    # 4. Append the checksum to the end of the private key
    private_key += checksum

    # 5. Encode the resulting key in Base58 format to get the final private key
    private_key = base58.b58encode(bytes.fromhex(private_key))

    # Print the final private key
    print('[Private Key]\n\t└──', private_key.decode())

    # ────────────────────────────────────────────────────────────── #

    # 033cc70bb17521031553b3af5f4b14510e3f2f79ad5d3c62f1dfc5156615195a1ec152684c068d09ac
    # 3BT2frZHUc3jVQLyL1CjrUwGKeqwEHACMR

    # ใช้ private key ไปคำนวณหาจุด public key ที่สอดคล้องกันบนเส้นโค้ง secp256k1
    public_key_point = int(entropy) * ecdsa.SECP256k1.generator
    print(public_key_point)

    # เข้ารหัสตรงจุด public key เป็น public key แบบย่อ
    if public_key_point.y() & 1:
      prefix = b"\x03"
    else:
       prefix = b"\x02"

    public_key = prefix + public_key_point.x().to_bytes(32, "big")

    # ตอนนี้ public key ถูกเข้ารหัสเป็น public key ที่ถูกบีบอัดในเส้นโค้ง secp256k1 curve
    print('[Public Key]\n\t└──', public_key.hex(), '\n')

    '''
    
    def create_private_key():
    private_key = os.urandom(32)
    private_key_hex = private_key.hex()
    return private_key_hex'''
