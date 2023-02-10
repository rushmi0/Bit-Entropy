import requests
import json

url = "https://lnbits.lightningok.win/paywall/api/v1/paywalls?api-key=a0944a58cfaa4ff3be3864e248ad2a23"
headers = {
    "accept": "application/json",
    "X-API-KEY": "217aa468d52e40c9ab3e4f00bfdbc32c",
    "Content-Type": "application/json"
}

data = {
    "url": "https://www.youtube.com/live/OwEmkZcqKYY?feature=share",
    "memo": "เดี่ยวกับซัน",
    "description": "YouTube",
    "amount": 999,
    "remembers": True
}

response = requests.post(url, headers=headers, data=json.dumps(data))

if response.status_code == 201:
    print(response.json())
else:
    print("Status Code:", response.status_code)