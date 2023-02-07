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

'''───────────────────────────────────────────────────────────────────────────'''

#pubkey1 = "0441cba5375257c757fc217c6341e14c160656c2c83c7c30f4bd5a611b101ed25f1f26465cd92f4a4bf1be722680edc6dc5845e984828c580c1a283478580b2992"
#pubkey2 = "04a77b667d3ad209199fd31e7855a071825601482bb1452e2b8137853881cde03817712ab0f4863e35f16f8d573c13ab2ae9696bba2dff88f6c14f7cd628b0a638"
#pubkey3 = "047b22b60a0afe67577c90a9b518cc5135a34f6ebaf8b48b95fe559e6de453becd54dd6491527127ddff7ca8e2955ca277237ad242e6aac1b2f158cd1919de22ca"


def main():
    for i in range(3):
        keys_stored = []
        print()
        option = int(input('[ Option Create a MultiSig ]\n'
                           '\t[1] MultiSig 3 of 3\n'
                           '\t[2] MultiSig 2 of 3\n'
                           '\t[3] MultiSig 1 of 3\n'
                           '\t[4] MultiSig 2 of 2\n'
                           '\t[5] MultiSig 1 of 2\n'
                           '\t[6] MultiSig 1 of 1\n'
                           ' >  : '))
        if option == 1:
            print('\n[Function MultiSig 3 of 3]')
            for i in range(3):
                keys = input('Enter public key %s\n > ' % (i+1))
                print()

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


        elif option == 2:
            print('\n[Function MultiSig 2 of 3]')
            for i in range(3):
                keys = input('Enter public key %s\n > ' % (i+1))
                print()

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid public key format!!")

            print('set key: ', keys_stored)
            Raw_Redeem_Script = multisig_2of3(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)

        elif option == 3:
            print('\n[Function MultiSig 1 of 3]')
            for i in range(3):
                keys = input('Enter public key %s\n > ' % (i+1))
                print()

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid public key format!!")
            Raw_Redeem_Script = multisig_1of3(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)


        elif option == 4:
            print('\n[Function MultiSig 2 of 2]')
            for i in range(3):
                keys = input('Enter public key %s\n > ' % (i+1))
                print()

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid public key format!!")
            Raw_Redeem_Script = multisig_2of2(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)


        elif option == 5:
            print('\n[Function MultiSig 1 of 2]')
            for i in range(3):
                keys = input('Enter public key %s\n > ' % (i+1))
                print()

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid public key format!!")
            Raw_Redeem_Script = multisig_1of2(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)


        elif option == 6:
            print('\n[Function MultiSig 1 of 1]')
            for i in range(3):
                keys = input('Enter public key %s\n > ' % (i+1))
                print()

                if check_public_key(keys) == True:
                    print("Valid public key format %s" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid public key format!!")
            Raw_Redeem_Script = multisig_1of1(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)

        else:
            print('Not in option!!')

if __name__ == "__main__":
    main()
