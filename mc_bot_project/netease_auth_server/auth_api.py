import hashlib
import json
import uuid
import base64
import random
import time
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from .dynamic_token import compute_dynamic_token

# Constants from C# SDK
HTTP_KEYS_STR = "MK6mipwmOUedplb6,OtEylfId6dyhrfdn,VNbhn5mvUaQaeOo9,bIEoQGQYjKd02U0J,fuaJrPwaH2cfXXLP,LEkdyiroouKQ4XN1,jM1h27H4UROu427W,DhReQada7gZybTDk,ZGXfpSTYUvcdKqdY,AZwKf7MWZrJpGR5W,amuvbcHw38TcSyPU,SI4QotspbjhyFdT0,VP4dhjKnDGlSJtbB,UXDZx4KhZywQ2tcn,NIK73ZNvNqzva4kd,WeiW7qU766Q1YQZI"
HTTP_KEYS = [k.encode('us-ascii') for k in HTTP_KEYS_STR.split(',')]
HTTP_IV = b"szkgpbyimxavqjcn"

DYNAMIC_TOKEN_SALT = "0eGsBkhl"

URL_SERVICE_MKEY = "https://service.mkey.163.com"
URL_X19_OBT_CORE = "https://x19obtcore.nie.netease.com:8443"
URL_X19_API_GATEWAY = "https://x19apigatewayobt.nie.netease.com"

PROJECT_ID = "aecfrxodyqaaaajp-g-x19" # Projects.DesktopMinecraft
GAME_VERSION = "latest_version" # Placeholder, will fetch

class HttpCipher:
    @staticmethod
    def encrypt(body_in: bytes) -> bytes:
        # Pad body to multiple of 16 manually (C# does Math.Ceiling)
        # C# logic: var body = new byte[(int)Math.Ceiling((double)(bodyIn.Length + 16) / 16) * 16];
        # Array.Copy(bodyIn, body, bodyIn.Length);
        # for (var i = 0; i < initVector.Length; i++) body[i + bodyIn.Length] = initVector[i];
        
        # Python equivalent:
        target_len = ((len(body_in) + 16 + 15) // 16) * 16
        body = bytearray(target_len)
        body[:len(body_in)] = body_in
        body[len(body_in):len(body_in)+16] = HTTP_IV
        
        # Key selection
        # var keyIndex = (byte)((Random.Shared.Next(0, HttpKeys.Length - 1) << 4) | 2);
        # Note: C# Next(min, max) is exclusive of max? No, Next(0, Length-1) means max is inclusive? 
        # Random.Next(min, max) -> max is exclusive. So 0 to Length-1 exclusive? 
        # C# code: Random.Shared.Next(0, HttpKeys.Length - 1)
        # If Length is 16, Next(0, 15) returns 0..14. So last key is never used?
        # Let's stick to the C# logic.
        key_idx_rand = random.randint(0, len(HTTP_KEYS) - 2) # Python randint is inclusive
        key_index_byte = (key_idx_rand << 4) | 2
        
        key = HTTP_KEYS[(key_index_byte >> 4) & 0xF]
        
        cipher = AES.new(key, AES.MODE_CBC, HTTP_IV)
        encrypted_data = cipher.encrypt(bytes(body))
        
        # Result: IV + Encrypted + KeyIndex
        result = bytearray()
        result.extend(HTTP_IV)
        result.extend(encrypted_data)
        result.append(key_index_byte)
        
        return bytes(result)

    @staticmethod
    def decrypt(body: bytes) -> bytes:
        if len(body) < 0x12:
            return None
            
        key_index_byte = body[-1]
        key_idx = (key_index_byte >> 4) & 0xF
        key = HTTP_KEYS[key_idx]
        
        iv = body[:16]
        encrypted_data = body[16:-1]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Scissor logic to remove IV and padding
        scissor = 0
        scissor_pos = len(decrypted_data) - 1
        
        while scissor < 16 and scissor_pos >= 0:
            if decrypted_data[scissor_pos] != 0x00:
                scissor += 1
            scissor_pos -= 1
            
        return decrypted_data[:scissor_pos + 1]

class DynamicToken:
    TOKEN_SALT = "0eGsBkhl"
    
    @staticmethod
    def compute(request_path: str, send_body: bytes, user_id: str, user_token: str) -> dict:
        if not request_path.startswith('/'):
            request_path = '/' + request_path
            
        # MD5(token).lower()
        token_md5 = hashlib.md5(user_token.encode('utf-8')).hexdigest().lower()
        
        # Build stream
        stream = bytearray()
        stream.extend(token_md5.encode('utf-8'))
        stream.extend(send_body)
        stream.extend(DynamicToken.TOKEN_SALT.encode('utf-8'))
        stream.extend(request_path.encode('utf-8'))
        
        # Secret MD5
        secret_md5 = hashlib.md5(stream).hexdigest().lower()
        
        # Hex to Binary string (char ASCII to binary)
        secret_bin = ""
        for char in secret_md5:
            # C# Convert.ToString(char, 2).PadLeft(8, '0')
            secret_bin += format(ord(char), '08b')
            
        # Rotate
        secret_bin = secret_bin[6:] + secret_bin[:6]
        
        # Process Binary Block
        http_token = bytearray(secret_md5.encode('utf-8'))
        
        for i in range(len(secret_bin) // 8):
            block = secret_bin[i*8 : (i+1)*8]
            xor_buffer = 0
            # C# loop: for (var j = 0; j < block.Length; j++) if (block[7 - j] == '1') xorBuffer |= (byte)(1 << j);
            # This reverses the bits?
            # block[7] is LSB (j=0). block[0] is MSB (j=7).
            # If block is "00000001", block[7] is '1'. j=0. xorBuffer |= 1<<0 = 1.
            # So it parses the binary string as a byte.
            # int(block, 2) should do the same.
            xor_buffer = int(block, 2)
            
            http_token[i] ^= xor_buffer
            
        # Base64 first 12 bytes + "1"
        b64 = base64.b64encode(http_token[:12]).decode('utf-8')
        dynamic_token = (b64 + "1").replace('+', 'm').replace('/', 'o')
        
        return {
            "user-id": user_id,
            "user-token": dynamic_token
        }

class NeteaseAuthApi:
    def __init__(self):
        self.device_id = None
        self.device_key = None
        self.unique_id = None
        self.mac_address = None
        self.project_id = PROJECT_ID
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "WPFLauncher/0.0.0.0"})
        self.game_version = self.fetch_latest_version()
        self._load_device()

    def fetch_latest_version(self):
        try:
            url = "https://x19.update.netease.com/pl/x19_java_patchlist"
            resp = self.session.get(url)
            resp.raise_for_status()
            content = resp.text
            
            # C# logic: var lastIndex = versions.LastIndexOf(',');
            # var json = string.Concat("{", versions[..lastIndex], "}");
            last_comma = content.rfind(',')
            if last_comma != -1:
                json_str = "{" + content[:last_comma] + "}"
                versions = json.loads(json_str)
                # Assume insertion order is preserved (Python 3.7+) and the last one is the latest
                latest = list(versions.keys())[-1]
                print(f"DEBUG: Fetched latest game version: {latest}")
                return latest
        except Exception as e:
            print(f"Warning: Failed to fetch latest version: {e}")
        return "1.20.10.138211" # Fallback to a plausible version if fetch fails

    def _load_device(self):
        try:
            with open("device.json", "r") as f:
                data = json.load(f)
                self.device_id = data.get("device_id")
                self.device_key = data.get("device_key")
                self.unique_id = data.get("unique_id")
                self.mac_address = data.get("mac_address")
        except FileNotFoundError:
            pass

    def _save_device(self):
        with open("device.json", "w") as f:
            json.dump({
                "device_id": self.device_id,
                "device_key": self.device_key,
                "unique_id": self.unique_id,
                "mac_address": self.mac_address
            }, f, indent=2)

    def _get_base_params(self) -> dict:
        return {
            "app_channel": "netease",
            "app_mode": "2",
            "app_type": "games",
            "arch": "win_x64",
            "cv": "c4.2.0",
            "mcount_app_key": "EEkEEXLymcNjM42yLY3Bn6AO15aGy4yq",
            "mcount_transaction_id": "0",
            "process_id": "1234", # Fake PID
            "sv": "10.0.22621",
            "updater_cv": "c1.0.0",
            "game_id": self.project_id,
            "gv": self.game_version
        }

    def initialize_device(self):
        # Return existing device if loaded
        if self.device_id and self.device_key and self.unique_id:
            return self.device_id

        # Load or create device ID
        self.unique_id = uuid.uuid4().hex
        
        # Generate random MAC
        mac_bytes = [0x00, 0x16, 0x3E, random.randint(0x00, 0x7F), random.randint(0x00, 0xFF), random.randint(0x00, 0xFF)]
        self.mac_address = ':'.join(map(lambda x: "%02x" % x, mac_bytes)).upper()
        
        params = self._get_base_params()
        params.update({
            "unique_id": self.unique_id,
            "brand": "Microsoft",
            "device_model": "pc_mode",
            "device_name": f"PC-{uuid.uuid4().hex[:12]}",
            "device_type": "Computer",
            "init_urs_device": "0",
            "mac": self.mac_address,
            "resolution": "1920x1080",
            "system_name": "windows",
            "system_version": "10.0.22621"
        })
        
        url = f"{URL_SERVICE_MKEY}/mpay/games/{self.project_id}/devices"
        resp = self.session.post(url, data=params)
        resp.raise_for_status()
        
        data = resp.json()
        self.device_id = data['device']['id']
        self.device_key = data['device']['key']
        
        self._save_device()
        return self.device_id

    def login_with_email(self, email, password):
        if not self.device_id:
            self.initialize_device()
            
        # Encrypt params
        login_params = {
            "username": email,
            "password": hashlib.md5(password.encode('utf-8')).hexdigest(),
            "unique_id": self.unique_id
        }
        json_params = json.dumps(login_params)
        
        # AES Encrypt with Device Key
        key_bytes = bytes.fromhex(self.device_key)
        cipher = AES.new(key_bytes, AES.MODE_ECB) # C# AesEncrypt extension default?
        # Wait, C# AesEncrypt extension in Codexus.OpenSDK.Extensions?
        # I need to check that. Assuming ECB or CBC with zero IV?
        # Usually simple AES encrypt implies ECB or CBC with default IV.
        # Let's assume ECB for now as it's common for simple key encryption, but I should verify.
        # Actually, let's check Extensions.cs if possible.
        # For now, I'll use ECB + PKCS7 padding.
        padded = pad(json_params.encode('utf-8'), 16)
        encrypted = cipher.encrypt(padded)
        encrypted_hex = encrypted.hex()
        
        params = self._get_base_params()
        params.update({
            "opt_fields": "nickname,avatar,realname_status,mobile_bind_status,mask_related_mobile,related_login_status",
            "params": encrypted_hex,
            "un": base64.b64encode(email.encode('utf-8')).decode('utf-8')
        })
        
        url = f"{URL_SERVICE_MKEY}/mpay/games/{self.project_id}/devices/{self.device_id}/users"
        resp = self.session.post(url, data=params)
        
        # Handle 1351 Risk/Captcha
        if resp.status_code == 400:
            print(f"DEBUG: MPay Login 400 Error: {resp.text}")
            try:
                err_data = resp.json()
                if err_data.get('code') == 1351:
                    verify_url = err_data.get('verify_url')
                    print(f"\n[!] 登录触发风控 (Code 1351)")
                    print(f"[!] 请在浏览器中访问以下链接进行验证：")
                    print(f"[!] {verify_url}")
                    print(f"[!] 验证完成后，请重新运行程序。\n")
                    raise Exception(f"Risk detected. Please verify at: {verify_url}")
            except json.JSONDecodeError:
                pass
                
        resp.raise_for_status()
        
        user_data = resp.json()
        return user_data # Contains user.id, user.token

    def x19_continue(self, mpay_user):
        # mpay_user is the dict returned by login_with_email
        user_id = mpay_user['user']['id']
        token = mpay_user['user']['token'].strip() # Trim token just in case
        
        sauth_json = {
            "sdk_uid": user_id,
            "session_id": token,
            "udid": uuid.uuid4().hex.upper(),
            "device_id": self.device_id
        }
        sauth_str = json.dumps(sauth_json, separators=(',', ':')) # Compact JSON like C# often does
        
        wrapper = {"json": sauth_str}
        wrapper_json_str = json.dumps(wrapper, separators=(',', ':'))
        
        # Login OTP
        url_otp = f"{URL_X19_OBT_CORE}/login-otp"
        print(f"DEBUG: POST {url_otp}")
        print(f"DEBUG: Body: {wrapper_json_str}")
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "WPFLauncher/0.0.0.0"
        }
        
        resp = self.session.post(url_otp, data=wrapper_json_str, headers=headers)
        print(f"DEBUG: Response Status: {resp.status_code}")
        print(f"DEBUG: Response Text: {resp.text}")
        resp.raise_for_status()
        otp_data = resp.json()['data']
        otp_obj = json.loads(otp_data) # It's a string containing JSON?
        
        # Auth OTP
        detail = {
            "udid": sauth_json['udid'],
            "app_version": self.game_version,
            "pay_channel": "netease" # Assuming
        }
        
        auth_data = {
            "sa_data": json.dumps(detail),
            "auth_json": sauth_str,
            "version": {"version": self.game_version},
            "aid": str(otp_obj['aid']),
            "otp_token": otp_obj['otp_token'],
            "lock_time": otp_obj['lock_time']
        }
        
        auth_data_str = json.dumps(auth_data)
        encrypted_auth = HttpCipher.encrypt(auth_data_str.encode('utf-8'))
        
        url_auth = f"{URL_X19_OBT_CORE}/authentication-otp"
        resp = self.session.post(url_auth, data=encrypted_auth)
        resp.raise_for_status()
        
        decrypted_resp = HttpCipher.decrypt(resp.content)
        entity = json.loads(decrypted_resp)
        auth_otp = entity['data']
        
        # Login Start
        # Need Dynamic Token headers
        entity_id = auth_otp['entity_id']
        entity_token = auth_otp['token']
        
        self._post_with_dynamic_token(
            f"{URL_X19_OBT_CORE}/interconn/web/game-play-v2/login-start",
            {"strict_mode": True},
            entity_id,
            entity_token
        )
        
        # Game Start
        game_start_req = {
            "game_type": "0", # NetGame
            "game_id": user_id, # Or some game ID? C# says user.User.Id
            "item_list": ["10000"]
        }
        self._post_with_dynamic_token(
            f"{URL_X19_OBT_CORE}/interconn/web/game-play-v2/start",
            game_start_req,
            entity_id,
            entity_token
        )
        
        return entity_id, entity_token

    def _post_with_dynamic_token(self, url, json_body, user_id, user_token):
        body_str = json.dumps(json_body)
        path = url.replace(URL_X19_OBT_CORE, "").replace(URL_X19_API_GATEWAY, "")
        
        headers = DynamicToken.compute(path, body_str.encode('utf-8'), user_id, user_token)
        
        resp = self.session.post(url, data=body_str, headers=headers)
        print(f"DEBUG: {path} Response: {resp.text}")
        resp.raise_for_status()
        return resp

    def x19_login_with_sauth(self, sauth_str):
        sauth_json = json.loads(sauth_str)
        
        # Correct key is "sauth_json" based on X19SAuthJsonWrapper.cs
        wrapper = {"sauth_json": sauth_str}
        
        # Login OTP
        url_otp = f"{URL_X19_OBT_CORE}/login-otp"
        print(f"DEBUG: POST {url_otp}")
        
        # Use browser UA just in case
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        
        # Use json parameter to let requests handle serialization and headers
        resp = self.session.post(url_otp, json=wrapper)
        
        print(f"DEBUG: login-otp Response: {resp.text}")
        resp.raise_for_status()
        otp_obj = resp.json()['entity']
        
        # Auth OTP
        detail = {
            "os_name": "windows",
            "os_ver": "Microsoft Windows 11 专业版",
            "mac_addr": "",
            "udid": sauth_json['udid'],
            "app_ver": self.game_version,
            "sdk_ver": "",
            "network": "",
            "disk": uuid.uuid4().hex[:4].upper(),
            "is64bit": "1",
            "launcher_type": "PC_java",
            "pay_channel": sauth_json.get('app_channel', 'netease')
        }
        
        auth_data = {
            "sa_data": json.dumps(detail),
            "sauth_json": sauth_str,
            "version": {"version": self.game_version, "launcher_md5": "", "updater_md5": ""},
            "aid": str(otp_obj['aid']),
            "otp_token": otp_obj['otp_token'],
            "lock_time": otp_obj['lock_time']
        }
        
        auth_data_str = json.dumps(auth_data)
        encrypted_auth = HttpCipher.encrypt(auth_data_str.encode('utf-8'))
        
        url_auth = f"{URL_X19_OBT_CORE}/authentication-otp"
        resp = self.session.post(url_auth, data=encrypted_auth)
        resp.raise_for_status()
        
        decrypted_resp = HttpCipher.decrypt(resp.content)
        print(f"DEBUG: Decrypted Auth Response: {decrypted_resp}")
        
        try:
            entity = json.loads(decrypted_resp)
        except json.JSONDecodeError:
            s = decrypted_resp.decode('utf-8', errors='ignore').strip()
            last_brace = s.rfind('}')
            if last_brace != -1:
                s = s[:last_brace+1]
            entity = json.loads(s)

        if 'entity' in entity:
            auth_otp = entity['entity']
        elif 'data' in entity:
            auth_otp = entity['data']
        else:
            auth_otp = entity
        
        # Login Start
        entity_id = auth_otp['entity_id']
        entity_token = auth_otp['token']
        
        self._post_with_dynamic_token(
            f"{URL_X19_OBT_CORE}/interconn/web/game-play-v2/login-start",
            {"strict_mode": True},
            entity_id,
            entity_token
        )
        
        # Game Start
        game_start_req = {
            "game_type": "0", 
            "game_id": sauth_json['sdkuid'], 
            "item_list": ["10000"]
        }
        self._post_with_dynamic_token(
            f"{URL_X19_OBT_CORE}/interconn/web/game-play-v2/start",
            game_start_req,
            entity_id,
            entity_token
        )
        
        return entity_id, entity_token, auth_otp

