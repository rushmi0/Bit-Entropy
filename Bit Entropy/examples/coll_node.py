import json
import requests


# ตั้งค่าสำหรับการเชื่อมต่อโหนดด้วย RPC
rpc_user = 'Mai'
rpc_password = 'Mai123'
rpc_port = 8332


auth = requests.auth.HTTPBasicAuth(rpc_user, rpc_password)
headers = {'content-type': 'application/json'}
url = f'http://localhost:{rpc_port}/'


num = 0
while True:
    num += 1
    print('─────────'*5)
    option = input('Input option\n'
                   '[1]Validate Address\n'
                   '[2]Broadcast\n'
                   '[3]Block Height\n'
                   '[4]Create Multisig\n'
                   '[5]Decode Script\n'
                   '[6]Decode Transaction\n'
                   ' >  : ')
    print()
    if option == "1":
        data = input('validate address %s\n input >  : ' % num)
        method = 'validateaddress'
        params = [data]
        # เตรียมข้อมูลสำหรับส่งคำขอไปยัง Bitcoin node
        payload = {
            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': num,
        }
        # ส่งคำขอไปยัง Bitcoin node
        response = requests.post(url, data=json.dumps(payload), headers=headers, auth=auth).json()

        # เรียกดูข้อมูล
        result = json.dumps(response['result'], indent=3)
        #print(result)
        if result == 111:
            error = json.dumps(response, indent=3)
            print(error)

        else:
            print('%s' % result)

    if option == "2":
        data = input('[Broadcast Transaction Into The Bitcoin Network]\n '
                     'Input Transaction > : ')
        method = 'sendrawtransaction'
        params = [data]
        # เตรียมข้อมูลสำหรับส่งคำขอไปยัง Bitcoin node
        payload = {
            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': num,
        }
        # ส่งคำขอไปยัง Bitcoin node
        response = requests.post(url, data=json.dumps(payload), headers=headers, auth=auth).json()

        # เรียกดูข้อมูล
        result = json.dumps(response['result'], indent=3)
        if result == 'null':
            error = json.dumps(response, indent=3)
            print(error)

        else:
            print('{}  {} '.format(method,result))

    if option == "3":
        method = 'getblockcount'
        params = []
        # เตรียมข้อมูลสำหรับส่งคำขอไปยัง Bitcoin node
        payload = {
            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': num,
        }
        # ส่งคำขอไปยัง Bitcoin node
        response = requests.post(url, data=json.dumps(payload), headers=headers, auth=auth).json()

        # เรียกดูข้อมูล
        result = json.dumps(response['result'], indent=3)
        if result == 'null':
            error = json.dumps(response, indent=3)
            print(error)
        else:
            print('Block Height : {} '.format(result))


    if option == "4":
        set_key = []

        # Specify amount of singnatures max 3, min 1:
        n_sig = int(input("Enter the Signatures required for unlock: "))
        # 0310096f2a0e92ce5fc10cf2fe2fec3887a42f130f8c23cc39b6e2f69fdb2d786f
        # 02ec55a7474b35c587f4b3c31d9e46933df0f72716700f3d16b4709e201cae61c4
        # 03ec55a7474b35c587f4b3c31d9e46933df0f72716700f3d16b4709e201cae61c4

        keys = int(input('Enter the keys to create MultiSig: '))
        for i in range(keys):
            pubkey = input('Enter your public key: ')
            set_key.append(pubkey)
            print(set_key)

        method = 'createmultisig'
        params = [n_sig, set_key]
        payload = {

            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': num,
        }
        response = requests.post(url, data=json.dumps(payload), headers=headers, auth=auth).json()
        result = json.dumps(response['result'], indent=3)
        if result == 'null':
            error = json.dumps(response, indent=3)
            print(error)
        else:
            print('%s' % result)

    if option == "5":
        data = input('[Decode Script]\n '
                     'Input Transaction > : ')
        method = 'decodescript'
        params = [data]
        # เตรียมข้อมูลสำหรับส่งคำขอไปยัง Bitcoin node
        payload = {
            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': num,
        }
        # ส่งคำขอไปยัง Bitcoin node
        response = requests.post(url, data=json.dumps(payload), headers=headers, auth=auth).json()
        result = json.dumps(response['result'], indent=3)
        if result == 'null':
            error = json.dumps(response, indent=3)
            print(error)

        else:
            print('%s' % result)
