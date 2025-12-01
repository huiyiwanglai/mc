import requests
import json

URL = "https://x19obtcore.nie.netease.com:8443/login-otp"
SAUTH_STR = '{"aim_info":"{\\"aim\\":\\"127.0.0.1\\",\\"tz\\":\\"+0800\\",\\"tzid\\":\\"\\",\\"country\\":\\"CN\\"}","app_channel":"4399pc","client_login_sn":"118c69898d7d4739bcce1a9014fc7ae7","deviceid":"118c69898d7d4739bcce1a9014fc7ae7","gameid":"x19","gas_token":"","ip":"127.0.0.1","login_channel":"4399pc","platform":"pc","realname":"{\\"realname_type\\":\\"0\\"}","sdk_version":"1.0.0","sdkuid":"4096708915","sessionid":"250405c7a539b9da9ec950216ff2e1c0","source_platform":"pc","timestamp":"1764444669933","udid":"118c69898d7d4739bcce1a9014fc7ae7","userid":"4653107966"}'

def test(name, **kwargs):
    print(f"--- Testing {name} ---")
    if 'headers' not in kwargs:
        kwargs['headers'] = {}
    kwargs['headers']['User-Agent'] = "WPFLauncher/0.0.0.0"
    kwargs['headers']['Accept'] = "application/json"
    
    try:
        resp = requests.post(URL, **kwargs)
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.text}")
        print(f"Request Headers: {resp.request.headers}")
        print(f"Request Body: {resp.request.body}")
    except Exception as e:
        print(f"Error: {e}")
    print()

# 1. Standard Wrapper (JSON Body) with explicit charset
wrapper = {"json": SAUTH_STR}
test("1. JSON Wrapper", json=wrapper, headers={"Content-Type": "application/json; charset=utf-8"})

# 9. Query Param
test("9. Query Param", params={"json": "{}"})

# 10. Raw String Body
test("10. Raw String Body", data='"{}"', headers={"Content-Type": "application/json"})

# 11. Raw String Body (No Quotes)
test("11. Raw String Body No Quotes", data='{}', headers={"Content-Type": "application/json"})
