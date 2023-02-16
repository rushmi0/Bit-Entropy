import subprocess
import json

addr = "12Fzx91T28kiYmczdJzLJJ3KYbLgc6uoC6"

address = "https://mempool.space/api/address/" + addr
output_address = subprocess.run(["curl", "-sSL", address], capture_output=True)

if output_address.returncode == 0:
    ON_CHAIN_DATA = json.loads(output_address.stdout)
    addr = json.dumps(ON_CHAIN_DATA["chain_stats"], indent=2)
    print(addr)
else:
    print(output_address.stderr.decode())