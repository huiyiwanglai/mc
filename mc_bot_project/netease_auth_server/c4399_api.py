import requests
import json
import time
import uuid
import random
import string
import urllib.parse
from urllib.parse import urlencode, quote

class C4399Api:
    APP_ID = "kid_wdsj"
    GAME_URL = "https://cdn.h5wan.4399sj.com/microterminal-h5-frame?game_id=500352"
    BIZ_ID = "2201001794"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        
    def login_with_password(self, username, password, session_id=None, captcha=None):
        params = self._build_login_parameters()
        params['username'] = username
        params['password'] = password
        
        if session_id is None and captcha is None:
            # Check if captcha is required
            url_check = "https://ptlogin.4399.com/ptlogin/loginFrame.do?v=1"
            resp = self.session.post(url_check, data=params)
            if "账号异常，请输入验证码" in resp.text:
                raise Exception("Captcha required")
                
        if session_id and captcha:
            params['sessionId'] = session_id
            params['inputCaptcha'] = captcha
            
        url_login = "https://ptlogin.4399.com/ptlogin/login.do?v=1"
        resp = self.session.post(url_login, data=params)
        
        if resp.status_code != 200:
             raise Exception(f"Login failed: {resp.status_code}")
             
        return self._generate_sauth()

    def _generate_sauth(self):
        timestamp = int(time.time())
        
        # Note: The order and exact format might matter for the signature or server expectation,
        # but requests handles urlencode.
        # C# uses a custom QueryBuilder, but standard urlencode should work if keys match.
        query_params = {
            "appId": self.APP_ID,
            "gameUrl": self.GAME_URL,
            "isCrossDomain": "1",
            "nick": "null",
            "onLineStart": "false",
            "ptLogin": "true",
            "rand_time": "$randTime", 
            "retUrl": self._build_redirect_url(timestamp),
            "show": "1"
        }
        
        query_str = urlencode(query_params)
        # C# uses GetAsync with query string appended
        url = f"https://ptlogin.4399.com/ptlogin/checkKidLoginUserCookie.do?{query_str}"
        
        resp = self.session.get(url)
        resp.raise_for_status()
        
        # Extract query string from the final URL (after redirects)
        final_url = resp.url
        if '?' not in final_url:
             raise Exception("Login to Pc499 failed (No query params in redirect URL)")
             
        query_part = final_url.split('?', 1)[1]
        
        # Get UniAuth
        uni_auth_params = self._get_uniauth(query_part)
        
        # Generate SAuth JSON
        return self._create_sauth_json(uni_auth_params)

    def _get_uniauth(self, query_str):
        timestamp = int(time.time())
        # jQuery callbacks usually use digits. C# StringGenerator(16, true, false, false) likely means numbers only?
        # Let's try digits only to be safe, or mixed.
        # But first, let's add debug logging.
        random_str = ''.join(random.choices(string.digits, k=16)) 
        callback = f"jQuery1830{random_str}_{timestamp}"
        
        params = {
            "callback": callback,
            "queryStr": query_str
        }
        
        url = f"https://microgame.5054399.net/v2/service/sdk/info"
        print(f"DEBUG: GetUniAuth URL: {url}")
        print(f"DEBUG: GetUniAuth Params: {params}")
        
        resp = self.session.get(url, params=params)
        print(f"DEBUG: GetUniAuth Response: {resp.text}")
        resp.raise_for_status()
        
        content = resp.text
        # Trim callback
        prefix = f"{callback}("
        if content.startswith(prefix):
            content = content[len(prefix):-1]
        else:
            # Sometimes it might not have the closing paren if we are unlucky with parsing?
            # But usually it does.
            if content.endswith(')'):
                 content = content[len(prefix):-1]
            else:
                 raise Exception(f"Unexpected callback format: {content[:50]}...")
            
        data = json.loads(content)
        # 4399 API seems to return 10000 for success
        if data.get('code') != 0 and data.get('code') != 10000:
            msg = data.get('message') or data.get('msg')
            raise Exception(f"UniAuth failed: {msg}")
            
        sdk_login_data = data['data']['sdk_login_data']
        # Parse query string format "username=xxx&uid=xxx..."
        return dict(urllib.parse.parse_qsl(sdk_login_data))

    def _create_sauth_json(self, params):
        # MgbSdk.GenerateSAuth
        # C# Guid.ToString("N") is lowercase.
        unique_id = uuid.uuid4().hex
        
        # Based on MgbSdkSAuthJson.cs
        payload = {
            "aim_info": '{"aim":"127.0.0.1","tz":"+0800","tzid":"","country":"CN"}',
            "app_channel": "4399pc",
            "client_login_sn": unique_id,
            "deviceid": unique_id,
            "gameid": "x19", 
            "gas_token": "",
            "ip": "127.0.0.1",
            "login_channel": "4399pc",
            "platform": "pc",
            "realname": '{"realname_type":"0"}',
            "sdk_version": "1.0.0",
            "sdkuid": params.get('uid'),
            "sessionid": params.get('token'),
            "source_platform": "pc",
            "timestamp": params.get('time'),
            "udid": unique_id,
            "userid": params.get('username')
        }
        # Use compact separators to match C# behavior if needed, though standard json is usually fine.
        return json.dumps(payload, separators=(',', ':'))

    def _build_login_parameters(self):
        return {
            "appId": self.APP_ID,
            "autoLogin": "on",
            "bizId": self.BIZ_ID,
            "css": "https://microgame.5054399.net/v2/resource/cssSdk/default/login.css",
            "displayMode": "popup",
            "externalLogin": "qq",
            "gameId": "wd",
            "iframeId": "popup_login_frame",
            "includeFcmInfo": "false",
            "layout": "vertical",
            "layoutSelfAdapting": "true",
            "level": "8",
            "loginFrom": "uframe",
            "mainDivId": "popup_login_div",
            "postLoginHandler": "default",
            "redirectUrl": "",
            "regLevel": "8",
            "sec": "1",
            "sessionId": "",
            "userNameLabel": "4399用户名",
            "userNameTip": "请输入4399用户名",
            "welcomeTip": "欢迎回到4399"
        }

    def _build_redirect_url(self, timestamp):
        # Note: C# uses explicit string concatenation with some URL encoding
        # We must match the encoding exactly as the server expects.
        # The C# code:
        # $"...&redirectUrl=http%3A%2F%2Fcdn.h5wan.4399sj.com%2Fmicroterminal-h5-frame%3Fgame_id%3D500352%26rand_time%3D{timestamp}"
        
        redirect_target = f"http://cdn.h5wan.4399sj.com/microterminal-h5-frame?game_id=500352&rand_time={timestamp}"
        # Documentation shows full encoding (including / -> %2F), so use safe=''
        encoded_redirect = quote(redirect_target, safe='')
        
        base = "https://ptlogin.4399.com/resource/ucenter.html"
        params = [
            "action=login",
            f"appId={self.APP_ID}",
            "loginLevel=8",
            "regLevel=8",
            f"bizId={self.BIZ_ID}",
            "externalLogin=qq",
            "qrLogin=true",
            "layout=vertical",
            "level=101",
            "css=https://microgame.5054399.net/v2/resource/cssSdk/default/login.css",
            "v=2018_11_26_16",
            "postLoginHandler=redirect",
            "checkLoginUserCookie=true",
            f"redirectUrl={encoded_redirect}"
        ]
        return base + "?" + "&".join(params)
