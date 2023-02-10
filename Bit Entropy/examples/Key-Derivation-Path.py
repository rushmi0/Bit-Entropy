import binascii
import hashlib
import hmac
import base58
import ecdsa


def generate_keys_from_seed(seed: bytes, prefix: bytes) -> tuple:

    private_key = hmac.new(key=prefix, msg=seed, digestmod=hashlib.sha512).digest()

    public_key_point = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1).verifying_key.pubkey.point

    if public_key_point.y() & 1:
        prefix = b"\x03"
    else:
        prefix = b"\x02"
    public_key = prefix + public_key_point.x().to_bytes(32, "big")

    return private_key, public_key



# ────────────────────────────────────────────────────────────────────────────────────────── #


def zprv_to_prikey(zprv: str, index: int) -> bytes:
    ''' เป็น private key derivation path  '''

    # ถอดรหัส zprv ที่เข้ารหัส base58 เพื่อรับข้อมูลดิบ
    data = base58.b58decode(zprv)

    # ดึงข้อมูลที่เกี่ยวข้องจาก zprv
    depth = data[4]
    parent_fingerprint = data[5:9]
    child_number = data[9:13]
    chain_code = data[13:45]
    private_key = data[46:78]

    # ใช้ chain code และตำแหน่ง child index เพื่อสร้างรหัสลูก
    child_key = hmac.new(chain_code, child_number + index.to_bytes(4, "big"), hashlib.sha512).digest()

    # คำนวณหา private key ของ child key โดยใช้ elliptic curve arithmetic
    curve = ecdsa.SECP256k1
    private_key = (int.from_bytes(private_key, "big") + int.from_bytes(child_key[:32], "big")) % curve.generator.order()

    # เข้ารหัส private key ด้วย base58 (string)
    private_key_b58 = base58.b58encode(private_key.to_bytes(32, "big")).decode("utf-8")

    return private_key_b58


# ────────────────────────────────────────────────────────────────────────────────────────── #


def xpub_to_pubkey(xpub: str, index: int) -> bytes:
    ''' เป็น public key derivation path  '''

    # ถอดรหัส xpub ที่เข้ารหัส base58 เพื่อรับข้อมูลดิบ
    data = base58.b58decode(xpub)

    # ดึงข้อมูลที่เกี่ยวข้องจาก xpub
    depth = data[4]
    parent_fingerprint = data[5:9]
    child_number = data[9:13]
    chain_code = data[13:45]
    public_key = data[45:78]

    # ใช้ chain_code และตำแหน่ง child index เพื่อสร้างรหัสลูก
    child_key = hmac.new(chain_code, child_number + index.to_bytes(4, "big"), hashlib.sha512).digest()

    # คำนวณหา public key ของ child key โดยใช้ elliptic curve arithmetic
    curve = ecdsa.SECP256k1
    public_key = ecdsa.VerifyingKey.from_string(public_key, curve=curve).pubkey.point + ecdsa.SigningKey.from_string(child_key[:32], curve=curve).verifying_key.pubkey.point
    public_key = ecdsa.VerifyingKey.from_public_point(public_key, curve=curve).to_string()

    # ส่งคืน public key ย่อยเป็น bytes object
    return public_key


# ────────────────────────────────────────────────────────────────────────────────────────── #


def pubkey_to_address(pubkey: bytes, version: int) -> str:
    # Hash public key ที่ได้จาก elliptic curve โดยใช้ SHA-256 และ RIPEMD-160
    sha256_hash = hashlib.sha256(pubkey).digest()
    hash160_hash = hashlib.new("ripemd160", sha256_hash).digest()

    # เพิ่ม version byte และตรวจสอบ public key ที่ hash แล้ว
    payload = version.to_bytes(1, "big") + hash160_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    payload += checksum

    # เข้ารหัส payload โดยใช้การเข้ารหัส base58
    # เป็นการตัดคำนำหน้าออก (b'1PCi2rTia9dcVz5Sng5DSmsi74bF2yXPfL') แล้วจะได้ (1PCi2rTia9dcVz5Sng5DSmsi74bF2yXPfL)
    address = base58.b58encode(payload).decode("utf-8")

    return address


# ────────────────────────────────────────────────────────────────────────────────────────── #


def child_pubkey_to_base16(child_pubkey_b58: str) -> str:
    # Decode the child public key from its base58 encoding
    child_pubkey = base58.b58decode(child_pubkey_b58)

    # Encode the decoded child public key as a base16-encoded string
    child_pubkey_hex = child_pubkey.hex()

    return child_pubkey_hex


# ────────────────────────────────────────────────────────────────────────────────────────── #


def __run__():
    ''' สำหรับการใช้งาน '''

    # zprv ที่ต้องการใช้เป็นคีย์หลัก
    zprv = "zprvAjJU6QR8LsUgC1rxpFh4D4PjKW87X9q3UzdMGRJZ6YWea1LQ2vJPU78cUdC6g8WZz9DvbxHxzDh1c8WY7V5h5L5n7B5AtM8m1h9QvZnxCZ"
    zpub = 'zpub6nqxsU6uvEX4ui5zcKpwb3nQAtmbcL2WZmQCWr9Wceiq8tNQh2LEmYajAmKjc3stFvAKk8KSHq1g2ZyGdw7BvcwdyYtQKTzCdwfz6Ue1ZsK'

    # xpub ที่ต้องการใช้เป็นคีย์หลัก
    xpub = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"

    for i in range(3):

        # เปลี่ยนเลขตรงนี้ได้ แล้วจะได้ Child-public-key และ Address ใหม่
        child_index = i

        # ส่งค่า 2ค่า (zprv, child_index หรือก็คือเลข i) ไปที่ `zprv_to_prikey` เพื่อรับ child private key
        child_prikey = zprv_to_prikey(zprv, child_index)

        # ส่งค่า 2ค่า (xpub, child_index หรือก็คือเลข i) ไปที่ `xpub_to_pubkey` เพื่อรับ child public key
        child_pubkey = xpub_to_pubkey(zpub, child_index)


        child_prikey_b58 = base58.b58encode(child_prikey).decode("utf-8")

        # เข้ารหัส public key ย่อย.. เป็น String (ข้อความ ไม่สามารถนำไปคำนวณทาง คณิตศาสตร์ได้) ที่เข้ารหัสด้วย base58
        child_pubkey_b58 = base58.b58encode(child_pubkey).decode("utf-8")


        print()

        # แสดงผล public key ย่อย
        # print('[Child Private Key]')
        # print('\t└── Derivation Path m/0/{}'.format(i))
        # print('\t\t└── {} {}\n'.format(child_prikey_b58, type(child_prikey_b58)))

        print('[Child Public Key]')
        print('\t└── Derivation Path "m/{}"'.format(i))
        print('\t\t└── {} {}\n'.format(child_pubkey_b58, type(child_pubkey_b58)))

        # นำ child public key ที่ได้มาและนำ `0x00` ส่งไปที่ `pubkey_to_address`
        address = pubkey_to_address(child_pubkey, 0x00)

        # เข้ารหัส address เป็นเลขฐาน16 รูปแบบ String
        address_hex = base58.b58encode_check(address).hex()

        child_pubkey_hex = child_pubkey_to_base16(child_pubkey_b58)
        print(child_pubkey_hex)

        # แสดงผล address รูปแบบ p2pkh
        print('[Bitcoin Address (p2pkh)]')
        print('\t└── Derivation Path "m/{}"'.format(i))
        print('\t\t└── {} {}\n'.format(address, type(address)))
        print('────'*27)


# ────────────────────────────────────────────────────────────────────────────────────────── #


if __name__ == "__main__":
    __run__()