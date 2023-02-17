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

""" Key Pair """
# Private Key :: KxGNJz64TfiVXJcxZ8VXbSjWpjeb7BKwg9LbdBMVdcj3y7nXaCh2
# Public Key :: 03ac908fa2e77a59cdbabcc1ed2a4511d21990e9f8b9c1f004b09c86a3702f83bc

# Private Key :: L22CDbMTehXgH48TkWqeFLvm43BZNJH3boB3PrV7oh6343m4JjMz
# Public Key :: 031ea37fbb27d6f4eecd038ed50db125bd6944983c46e6fdfc3a435b28e6aadf04

# Private Key :: L3fvCHsFfhUeuwoCwqqEjcT7P1rAz3nHrthcn8FcSb8KDTzCGib3
# Public Key :: 0207e9cf293331471df3c607ed62cda81c39e7de208bdb87f12f7290b7b63f977d

def main():
    for i in range(6):
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

                if check_public_key(keys) == True and is_base16(keys) == True:
                    print("Valid Public Key [%s]" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid Public Key!!")
                    break
                print()
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

                if check_public_key(keys) == True and is_base16(keys) == True:
                    print("Valid Public Key [%s]" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid Public Key!!")
                    break
                print()
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

                if check_public_key(keys) == True and is_base16(keys) == True:
                    print("Valid Public Key [%s]" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid Public Key!!")
                    break
                print()
            Raw_Redeem_Script = multisig_1of3(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)


        elif option == 4:
            print('\n[Function MultiSig 2 of 2]')
            for i in range(2):
                keys = input('Enter public key %s\n > ' % (i+1))

                if check_public_key(keys) == True and is_base16(keys) == True:
                    print("Valid Public Key [%s]" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid Public Key!!")
                    break
                print()
            Raw_Redeem_Script = multisig_2of2(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)


        elif option == 5:
            print('\n[Function MultiSig 1 of 2]')
            for i in range(2):
                keys = input('Enter public key %s\n > ' % (i+1))

                if check_public_key(keys) == True and is_base16(keys) == True:
                    print("Valid Public Key [%s]" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid Public Key!!")
                    break
                print()
            Raw_Redeem_Script = multisig_1of2(keys_stored)
            Redeem_Script = Raw_Redeem_Script.hex()

            Locking_Script = locking_script(Raw_Redeem_Script)
            print('\n'
                  'Redeem Script: %s' % Redeem_Script)
            print('Locking Script %s ' % Locking_Script)


        elif option == 6:
            print('\n[Function MultiSig 1 of 1]')
            for i in range(1):
                keys = input('Enter public key %s\n > ' % (i+1))

                if check_public_key(keys) == True and is_base16(keys) == True:
                    print("Valid Public Key [%s]" % keys)
                    keys_stored.append(keys)
                else:
                    print("Invalid Public Key!!")
                    break
                print()
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
