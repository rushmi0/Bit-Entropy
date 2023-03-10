import hashlib
import binascii
import ripemd160
import base58

'''────────────────────────────────  OP_CODE  ────────────────────────────────'''

OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_CHECKMULTISIG = 0xae

'''───────────────────────────────────────────────────────────────────────────'''

def locking_script(redeem_script) -> str:
    redeem_script = redeem_script
    SHA256 = hashlib.sha256(redeem_script).digest()
    RIPEMD160 = ripemd160.ripemd160(SHA256)
    p2sh = bytes([0x05]) + RIPEMD160
    p2sh = p2sh + hashlib.sha256(hashlib.sha256(p2sh).digest()).digest()[:4]
    p2sh = base58.b58encode(p2sh)
    locking = p2sh.decode()
    return locking

'''───────────────────────────────────────────────────────────────────────────'''

def is_base16(data):
    try:
        if int(data, 16):
            return True
        else:
            return False
    except ValueError:
        return False

'''───────────────────────────────────────────────────────────────────────────'''

def check_public_key(public_key) -> bool:
    if len(public_key) == 66:
        if public_key[0:2] == "02":
            return True
    if len(public_key) == 66:
        if public_key[0:2] == "03":
            return True
    elif len(public_key) == 130:
        if public_key[0:2] == "04":
            return True
    elif len(public_key) == 64:
        if int(public_key[0:2], 16) in [2, 3, 4]:
            return True
    return False

'''───────────────────────────────────────────────────────────────────────────'''

def multisig_3of3(pubkey=[]) -> bytes:
    pubkey1 = binascii.unhexlify(pubkey[0])
    pubkey2 = binascii.unhexlify(pubkey[1])
    pubkey3 = binascii.unhexlify(pubkey[2])
    Redeem_Script = (
            bytes([OP_3]) +
            len(pubkey1).to_bytes(1, 'big') + pubkey1 +
            len(pubkey2).to_bytes(1, 'big') + pubkey2 +
            len(pubkey3).to_bytes(1, 'big') + pubkey3 +
            bytes([OP_3, OP_CHECKMULTISIG])
    )
    script = Redeem_Script
    return script

def multisig_2of3(pubkey=[]) -> bytes:
    pubkey1 = binascii.unhexlify(pubkey[0])
    pubkey2 = binascii.unhexlify(pubkey[1])
    pubkey3 = binascii.unhexlify(pubkey[2])
    Redeem_Script = (
            bytes([OP_2]) +
            len(pubkey1).to_bytes(1, 'big') + pubkey1 +
            len(pubkey2).to_bytes(1, 'big') + pubkey2 +
            len(pubkey3).to_bytes(1, 'big') + pubkey3 +
            bytes([OP_3, OP_CHECKMULTISIG])
    )
    script = Redeem_Script
    return script

def multisig_1of3(pubkey=[]) -> bytes:
    pubkey1 = binascii.unhexlify(pubkey[0])
    pubkey2 = binascii.unhexlify(pubkey[1])
    pubkey3 = binascii.unhexlify(pubkey[2])
    Redeem_Script = (
            bytes([OP_1]) +
            len(pubkey1).to_bytes(1, 'big') + pubkey1 +
            len(pubkey2).to_bytes(1, 'big') + pubkey2 +
            len(pubkey3).to_bytes(1, 'big') + pubkey3 +
            bytes([OP_3, OP_CHECKMULTISIG])
    )
    script = Redeem_Script
    return script

'''───────────────────────────────────────────────────────────────────────────'''

def multisig_2of2(pubkey=[]) -> bytes :
    public_key1 = binascii.unhexlify(pubkey[0])
    public_key2 = binascii.unhexlify(pubkey[1])
    script = bytearray([OP_2, len(public_key1)]) + public_key1 + bytearray([len(public_key2)]) + public_key2 + bytearray([OP_2, OP_CHECKMULTISIG])
    return script

def multisig_1of2(pubkey=[]) -> bytes :
    public_key1 = binascii.unhexlify(pubkey[0])
    public_key2 = binascii.unhexlify(pubkey[1])
    script = bytearray([OP_1, len(public_key1)]) + public_key1 + (bytearray([len(public_key2)]) + public_key2) + bytearray([OP_2, OP_CHECKMULTISIG])
    return script

'''───────────────────────────────────────────────────────────────────────────'''

def multisig_1of1(pubkey=[]) -> bytes :
    public_key1 = binascii.unhexlify(pubkey[0])
    script = bytearray([OP_1, len(public_key1)]) + public_key1 + bytearray([OP_1, OP_CHECKMULTISIG])
    return script

