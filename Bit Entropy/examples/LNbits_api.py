import subprocess
import json

apiKey = "a0944a58cfaa4ff3be3864e248ad2a23"

headers = ["-H", "accept: application/json", "-H", "X-API-KEY: a0944a58cfaa4ff3be3864e248ad2a23"]
url = "https://lnbits.lightningok.win/api/v1/wallet?api-key=" + apiKey

output = subprocess.run(["curl", "-X", "GET", url] + headers, capture_output=True)

if output.returncode == 0:
    data = json.loads(output.stdout)
    print(json.dumps(data, indent=2))
else:
    print(output.stderr.decode())
