import requests
import json

READ_KEY = "a0944a58cfaa4ff3be3864e248ad2a23"
ADMIN_KEY = "217aa468d52e40c9ab3e4f00bfdbc32c"

url = "https://lnbits.lightningok.win/paywall/api/v1/paywalls?api-key=" + READ_KEY
headers = {
    "accept": "application/json",
    "X-API-KEY": ADMIN_KEY,
    "Content-Type": "application/json"
}

data = {
    "url": "https://www.youtube.com/live/OwEmkZcqKYY?feature=share",
    "memo": "เดี่ยวกับซัน",
    "description": "YouTube",
    "amount": 787,
    "remembers": True
}

response = requests.post(url, headers=headers, data=json.dumps(data))


if response.status_code == 200:
    print(json.dumps(response.json(), indent=2))
else:
    print("Status Code: %s" % response.status_code)
