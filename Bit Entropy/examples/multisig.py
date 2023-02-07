import re
import hashlib
import binascii
import ripemd160
import base58

'''  OP_CODE  '''
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_CHECKMULTISIG = 0xae

def locking_script(redeem_script) -> str:
    redeem_script = redeem_script
    SHA256 = hashlib.sha256(redeem_script).digest()
    RIPEMD160 = ripemd160.ripemd160(SHA256)
    p2sh = bytes([0x05]) + RIPEMD160
    p2sh = p2sh + hashlib.sha256(hashlib.sha256(p2sh).digest()).digest()[:4]
    p2sh = base58.b58encode(p2sh)
    locking = p2sh.decode()
    return locking

def is_base16(data):
    try:
        if int(data, 16):
            return True
        else:
            return False
    except ValueError:
        return False

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


def multisig_3of3(pubkey=[]) -> bytes:
    pubkey1 = bytes.fromhex(pubkey[0])
    pubkey2 = bytes.fromhex(pubkey[1])
    pubkey3 = bytes.fromhex(pubkey[2])

    REDEEM_SCRIPT = (
            bytes([OP_3]) +
            len(pubkey1).to_bytes(1, 'big') + pubkey1 +
            len(pubkey2).to_bytes(1, 'big') + pubkey2 +
            len(pubkey3).to_bytes(1, 'big') + pubkey3 +
            bytes([OP_3, OP_CHECKMULTISIG])
    )
    script = REDEEM_SCRIPT
    return script

def multisig_2of3(pubkey=[]) -> bytes:
    pubkey1 = binascii.unhexlify(pubkey[0])
    pubkey2 = binascii.unhexlify(pubkey[1])
    pubkey3 = binascii.unhexlify(pubkey[2])

    REDEEM_SCRIPT = (
            bytes([OP_2]) +
            len(pubkey1).to_bytes(1, 'big') + pubkey1 +
            len(pubkey2).to_bytes(1, 'big') + pubkey2 +
            len(pubkey3).to_bytes(1, 'big') + pubkey3 +
            bytes([OP_3, OP_CHECKMULTISIG])
    )
    script = REDEEM_SCRIPT
    return script

def multisig_1of3(pubkey=[]) -> bytes:
    pubkey1 = bytes.fromhex(pubkey[0])
    pubkey2 = bytes.fromhex(pubkey[1])
    pubkey3 = bytes.fromhex(pubkey[2])

    REDEEM_SCRIPT = (
            bytes([OP_1]) +
            len(pubkey1).to_bytes(1, 'big') + pubkey1 +
            len(pubkey2).to_bytes(1, 'big') + pubkey2 +
            len(pubkey3).to_bytes(1, 'big') + pubkey3 +
            bytes([OP_3, OP_CHECKMULTISIG])
    )
    script = REDEEM_SCRIPT
    return script

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

def multisig_1of1(pubkey=[]) -> bytes :
    public_key1 = binascii.unhexlify(pubkey[0])
    script = bytearray([OP_1, len(public_key1)]) + public_key1 + bytearray([OP_2, OP_CHECKMULTISIG])
    return script

p1 = "0441cba5375257c757fc217c6341e14c160656c2c83c7c30f4bd5a611b101ed25f1f26465cd92f4a4bf1be722680edc6dc5845e984828c580c1a283478580b2992"

p2 = "04a77b667d3ad209199fd31e7855a071825601482bb1452e2b8137853881cde03817712ab0f4863e35f16f8d573c13ab2ae9696bba2dff88f6c14f7cd628b0a638"

p3 = "047b22b60a0afe67577c90a9b518cc5135a34f6ebaf8b48b95fe559e6de453becd54dd6491527127ddff7ca8e2955ca277237ad242e6aac1b2f158cd1919de22ca"

pubkey = [p1, p2]
print(is_base16("mmm"))
script = multisig_1of2(pubkey)
print(script.hex())

'''
if __name__ == "__main__":
    for i in range(3):
        keys_stored = []

        print()
        n_sig = int(input("Enter the Signatures required for unlock: "))

        key = int(input('Enter the keys to create MultiSig: '))

        if n_sig == 1 and key == 3:
            for i in range(3):
                print()
                keys = input('Enter your public key: ')

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                elif keys == '':
                    pass
                else:
                    print("Invalid public key format!!")
            Raw_Redeem_Script = multisig_1of3(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)

        elif n_sig == 2 and key == 3:
            for i in range(3):
                print()
                keys = input('Enter your public key: ')

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                elif keys == '':
                    pass
                else:
                    print("Invalid public key format!!")

            print('set key: ', keys_stored)
            Raw_Redeem_Script = multisig_2of3(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            #Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            #print('Locking Script %s ' % Locking_Script)

        elif n_sig == 3 and key == 3:
            for i in range(3):
                print()
                keys = input('Enter your public key: ')

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid public key format!!")
            Raw_Redeem_Script = multisig_3of3(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)

        else:
            print('Not in option!!')
'''