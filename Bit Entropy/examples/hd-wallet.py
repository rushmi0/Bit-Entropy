from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit import bip39, bip32, ec
from binascii import hexlify
import os

'''
ความยาวเอนโทรปีเริ่มต้น (128-256บิต) : ENT
ความยาวเช็คซัม : CS
ความยาวของประโยคช่วยจำ : MS

CS = ENT / 32
MS = (ENT + CS) / 11
'''
'''
#  entropy = bytes(random.getrandbits(8) for i in range(16))
#  print("Entropy: " + str(entropy))
'''
print('[ HD Wallet!! ]')

def build(cal:str):
    if cal == "0" or cal == "1" or cal == "2" or cal == "3" or cal == "4":
        length = BITS[int(cal)]
        length_binary = BITS[int(cal)]
        print()
        entropy_2 = os.urandom(length // 8)
        #print(len(entropy_2), entropy_2)
        mnemonic = bip39.mnemonic_from_bytes(entropy_2)
        #mnemonic = "super choice radio shuffle glimpse copper pipe burger scorpion share gossip certain"
        seed = bip39.mnemonic_to_seed(mnemonic)


        xprv = bip32.HDKey.from_seed(seed, version=NETWORKS["main"]["xprv"])

        zprv = bip32.HDKey.from_seed(seed, version=NETWORKS["main"]["zprv"])
        yprv = bip32.HDKey.from_seed(seed, version=NETWORKS["main"]["yprv"]) # xprv, zprv, yprv

        pieces = mnemonic.split(' ')
        word = []
        for piece in pieces:
            word.append(piece)


        #print('├──')
        print("Mnemonic: [ {} ]".format(mnemonic))
        print('\t└── {} Word, {} Bits'.format(len(word), length))
        ln()

        # root privkey
        #zprv = bip32.HDKey.from_seed(seed)
        print("[Master Private Key] \n\t└── " + str(xprv))
        print('\t└── %s'%zprv)
        print('\t└── %s'%yprv)



        print()

        xpub = xprv.derive("m/84h/0h/0h").to_public()
        zpub = zprv.derive("m/84h/0h/0h").to_public()
        ypub = yprv.derive("m/84h/0h/0h").to_public()

        print("[Master Public Key] \n\t└── %s"% xpub)
        print('\t└── %s'%zpub)
        print('\t└── %s'%ypub)

        ln()

        # embit module, teach me how to use all function in ec
        locking_script = ["pkh", "wpkh", "tr"]
        addr_type = locking_script[0]
        desc = Descriptor.from_string("%s([%s/84h/0h/0h]%s/{0,1}/*)" % (addr_type, hexlify(yprv.my_fingerprint).decode(), xpub))
        #print(type(desc), desc)
        # desc = wpkh([e91aec37/84h/0h/0h]xpub6Cn5rGDCLNAsBVDxdP2X1Gi23LiL7HtZMPdtx11RJH8PsHDDLsuoXRd4VBy4YMawyLgbT1MGsbULntvD1WVU1mH6NtLCegEmcoECdLz8NK9/{0,1}/*)

        #amount = int(input("Enter your amount address: "))
        print('\t\t[locking type p2%s]'% addr_type)
        for i in range(5):
            print('\t','-' * 50)
            lock = desc.derive(i).address()
            if len(lock) > 42:
                Frist = lock[:17]
                Last = lock[-17:]
                result = Frist + '.........' + Last
                print('\t',i + 1, "| ", result)
            else:
                print('\t',i + 1, "| ", lock)

            pubkey = ec.PrivateKey.sec(xpub)
            #private_key = ec.PrivateKey(secret)
            print(pubkey.hex())
            #print(private_key)

            #prikey = ec.PrivateKey.wif(root)
            #print('\t',i + 1, "| ", desc.derive(i))
            #print('-' * 50)
    else:
        print()
        ln()
        print('\t\t[Not in option!!]')


def ln():
    print()
    print('────' * 30, '\n')



if __name__ == "__main__":
    BITS = [128, 160, 192, 224, 256]
    index=1
    while True:
        ln()
        Select = input('select | [1] 12word | [2] 15word | [3] 18word | [4] 21word | [5] 24word |: ')
        if Select == 'e' or Select == 'E':
            print()
            ln()
            print('\t\t[Stop!!]')
            break
        Result = int(Select)-index
        build(str(Result))
