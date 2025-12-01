import socket
import struct
import json
import os
import threading
import time
import logging
import uuid
import argparse
import random
import string
import zlib
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import sys
import math

try:
    import yaml
    _HAS_YAML = True
except Exception:
    yaml = None
    _HAS_YAML = False

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from netease_auth_server.client import NeteaseClient
except ImportError:
    NeteaseClient = None

try:
    from netease_auth_server.auth_api import NeteaseAuthApi
except ImportError:
    NeteaseAuthApi = None

try:
    from netease_auth_server.c4399_api import C4399Api
except ImportError:
    C4399Api = None

# --- Configuration ---
SERVER_ADDRESS = "117.147.207.62"
SERVER_PORT = 10162
PROTOCOL_VERSION = 340
MC_VERSION = "1.12.2"
LAUNCHER_VERSION = "1.15.11.28622"

# Auth Configuration
USE_NETEASE_AUTH = True
USE_4399_LOGIN = True

# Account List (Format: "username:password")
ACCOUNTS = [
    "4653107966:95543912",
    "69084800481:58064329",
    "079876642:24656567",
    "53876466499:11304878",
    "04310012351:07408672",
    # Add more accounts here
    # "username2:password",
    # "username3:password",
]

# Bot Configuration
BOT_NAME_PREFIX = "Bot_"

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('multi_bot_client.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

# Helper Functions
def read_varint_from_bytes(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("read_varint_from_bytes 要求 bytes-like 对象")
    data = bytes(data)
    num_read = 0
    result = 0
    shift = 0
    for i, byte in enumerate(data):
        byte = int(byte)
        result |= (byte & 0x7F) << shift
        shift += 7
        num_read += 1
        if num_read > 5:
            raise IOError("⚠️ VarInt过长或无效")
        if not (byte & 0x80):
            return result, i + 1
    raise IOError("⚠️ 未能从字节数组中读取完整的VarInt")

def pack_varint(value):
    data = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        data.append(byte)
        if value == 0:
            break
    return bytes(data)

def pack_string(string):
    string_bytes = string.encode('utf-8')
    length = pack_varint(len(string_bytes))
    return length + string_bytes

def compute_server_hash(server_id, shared_secret, public_key_der):
    m = hashlib.sha1()
    try:
        m.update(server_id.encode('utf-8'))
    except Exception:
        m.update(b'')
    m.update(shared_secret)
    m.update(public_key_der)
    digest = m.digest()
    num = int.from_bytes(digest, byteorder='big', signed=True)
    if num < 0:
        return '-' + format(-num, 'x')
    else:
        return format(num, 'x')

class PlayerState:
    def __init__(self):
        self.health = None
        self.food = None
        self.saturation = None
        self.x = 100.0
        self.y = 65.0
        self.z = 100.0
        self.yaw = 0.0
        self.pitch = 0.0
        self.on_ground = True

    def is_dead(self):
        try:
            return self.health is not None and self.health <= 0
        except Exception:
            return False

class BotClient(threading.Thread):
    def __init__(self, username, access_token=None, selected_profile=None):
        super().__init__()
        self.username = username
        self.access_token = access_token
        self.selected_profile = selected_profile
        
        self.sock = None
        self.running = True
        self.lock = threading.Lock()
        
        self.compression_threshold = None
        self.encryptor = None
        self.decryptor = None
        
        self.current_state = 0 # STATE_HANDSHAKE
        self.player_state = PlayerState()
        self.player_entity_id = None
        self.request_respawn = False
        
        self.position_update_interval = 0.05

    def log(self, message, level=logging.INFO):
        logger.log(level, f"[{self.username}] {message}")

    def run(self):
        self.log("启动机器人线程")
        self.connect_and_loop()

    def connect_and_loop(self):
        max_reconnect_attempts = 9999
        reconnect_delay = 5

        for attempt in range(max_reconnect_attempts):
            if not self.running:
                break
            try:
                self.sock = self.connect_to_server()
                if not self.sock:
                    time.sleep(reconnect_delay)
                    continue

                self.encryptor = None
                self.decryptor = None
                
                while self.running:
                    result = self.read_packet()
                    if result is None:
                        break
                    
                    packet_id, data = result
                    self.handle_packet(packet_id, data)
                    
                    # Check respawn
                    if self.request_respawn:
                        self.request_respawn = False
                        self.send_client_status(action=0) # Respawn

            except Exception as e:
                self.log(f"连接异常: {e}", level=logging.ERROR)
            finally:
                if self.sock:
                    try:
                        self.sock.close()
                    except:
                        pass
                    self.sock = None
            
            if self.running:
                self.log(f"等待 {reconnect_delay} 秒后重连...")
                time.sleep(reconnect_delay)

    def connect_to_server(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            self.log(f"正在连接到 {SERVER_ADDRESS}:{SERVER_PORT}")
            sock.connect((SERVER_ADDRESS, SERVER_PORT))
            
            self.send_handshake_packet(sock)
            self.current_state = 2 # STATE_LOGIN
            self.send_login_start_packet(sock)
            
            return sock
        except Exception as e:
            self.log(f"连接失败: {e}", level=logging.ERROR)
            return None

    def send_packet(self, packet_id, data):
        with self.lock:
            try:
                if not self.sock:
                    return False
                
                packet_data = pack_varint(packet_id) + (data if isinstance(data, (bytes, bytearray)) else bytes(data))
                
                if self.compression_threshold is not None:
                    if len(packet_data) >= self.compression_threshold:
                        uncompressed_data = packet_data
                        compressed_data = zlib.compress(uncompressed_data)
                        packet_data = pack_varint(len(uncompressed_data)) + compressed_data
                    else:
                        packet_data = pack_varint(0) + packet_data
                
                length = pack_varint(len(packet_data))
                packet = length + packet_data
                
                if self.encryptor:
                    packet = self.encryptor.update(packet)
                
                self.sock.sendall(packet)
                return True
            except Exception as e:
                self.log(f"发送数据包出错: {e}", level=logging.ERROR)
                return False

    def read_packet(self):
        try:
            length = self.read_varint()
            packet_data = bytearray()
            while len(packet_data) < length:
                chunk = self.sock.recv(length - len(packet_data))
                if not chunk:
                    raise IOError("连接关闭")
                if self.decryptor:
                    chunk = self.decryptor.update(bytes(chunk))
                packet_data.extend(chunk)
            
            index = 0
            if self.compression_threshold is not None:
                data_length, varint_len = read_varint_from_bytes(packet_data)
                index += varint_len
                if data_length != 0:
                    packet_data = zlib.decompress(bytes(packet_data[index:]))
                else:
                    packet_data = bytes(packet_data[index:])
            else:
                packet_data = bytes(packet_data)
            
            packet_id, packet_id_length = read_varint_from_bytes(packet_data)
            data = packet_data[packet_id_length:]
            return packet_id, data
        except Exception as e:
            self.log(f"读取数据包出错: {e}", level=logging.ERROR)
            return None

    def read_varint(self):
        num_read = 0
        result = 0
        shift = 0
        while True:
            byte = self.sock.recv(1)
            if not byte:
                raise IOError("连接关闭")
            if self.decryptor:
                dec = self.decryptor.update(bytes(byte))
                if not dec:
                    # Sometimes update buffers, need to read more? 
                    # For CFB8, 1 byte in -> 1 byte out usually.
                    continue 
                byte = dec[0]
            else:
                byte = byte[0]
            
            result |= (byte & 0x7F) << shift
            shift += 7
            num_read += 1
            if num_read > 5:
                raise IOError("VarInt过长")
            if not (byte & 0x80):
                break
        return result

    def send_handshake_packet(self, sock):
        host_str = SERVER_ADDRESS + "\0FML\0"
        data = pack_varint(PROTOCOL_VERSION) + pack_string(host_str) + struct.pack('>H', SERVER_PORT) + pack_varint(2)
        # Handshake is never encrypted/compressed initially
        # We use a temporary send because self.sock might not be set or we want to be explicit
        # But here we can use sock.sendall directly as it's raw
        packet_data = pack_varint(0x00) + data
        length = pack_varint(len(packet_data))
        sock.sendall(length + packet_data)

    def send_login_start_packet(self, sock):
        data = pack_string(self.username)
        # Login Start is 0x00
        packet_data = pack_varint(0x00) + data
        length = pack_varint(len(packet_data))
        sock.sendall(length + packet_data)

    def handle_packet(self, packet_id, data):
        if self.current_state == 2: # LOGIN
            if packet_id == 0x01: # Encryption Request
                self.handle_encryption_request(data)
            elif packet_id == 0x02: # Login Success
                self.handle_login_success(data)
            elif packet_id == 0x03: # Set Compression
                self.compression_threshold, _ = read_varint_from_bytes(data)
                self.log(f"压缩阈值设置为: {self.compression_threshold}")
        elif self.current_state == 3: # PLAY
            self.process_play_packet(packet_id, data)

    def handle_encryption_request(self, data):
        index = 0
        server_id_len, l = read_varint_from_bytes(data)
        index += l
        server_id = data[index:index+server_id_len].decode('utf-8')
        index += server_id_len
        
        pk_len, l = read_varint_from_bytes(data[index:])
        index += l
        public_key = data[index:index+pk_len]
        index += pk_len
        
        vt_len, l = read_varint_from_bytes(data[index:])
        index += l
        verify_token = data[index:index+vt_len]
        
        shared_secret = os.urandom(16)
        public_key_obj = serialization.load_der_public_key(public_key, backend=default_backend())
        
        encrypted_shared_secret = public_key_obj.encrypt(shared_secret, padding.PKCS1v15())
        encrypted_verify_token = public_key_obj.encrypt(verify_token, padding.PKCS1v15())
        
        # Netease Auth
        if USE_NETEASE_AUTH:
            server_hash = compute_server_hash(server_id, shared_secret, public_key)
            self.join_netease_session(server_hash)
            
        resp = pack_varint(len(encrypted_shared_secret)) + encrypted_shared_secret + pack_varint(len(encrypted_verify_token)) + encrypted_verify_token
        self.send_packet(0x01, resp)
        
        cipher = Cipher(algorithms.AES(shared_secret), modes.CFB8(shared_secret), backend=default_backend())
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        self.log("加密已启用")

    def join_netease_session(self, server_hash):
        if not NeteaseClient:
            return
        
        # Try to find auth servers
        candidates = [("106.2.44.63", 8095)]
        try:
            with urllib.request.urlopen("https://x19.update.netease.com/authserver.list", timeout=5) as r:
                d = json.loads(r.read().decode('utf-8'))
                for i in d:
                    candidates.append((i.get('IP') or i.get('ip'), i.get('Port') or i.get('port')))
        except:
            pass
            
        random.shuffle(candidates)
        
        # Use SELECTED_PROFILE as username for NeteaseClient if available (it's the EntityID)
        # For bots, if we don't have unique EntityIDs, this might fail or kick other bots.
        # But we try anyway.
        client_username = self.selected_profile if self.selected_profile and self.selected_profile.isdigit() else self.username
        
        for ip, port in candidates:
            try:
                client = NeteaseClient(ip, port, client_username, self.access_token, launcher_version=LAUNCHER_VERSION, game_version=MC_VERSION)
                client.connect()
                client.join_server(server_hash)
                self.log(f"网易验证成功 ({ip}:{port})")
                return
            except Exception as e:
                pass
        self.log("网易验证全部失败", level=logging.WARNING)

    def handle_login_success(self, data):
        self.current_state = 3 # PLAY
        self.log("登录成功! 进入游戏状态")
        # Start position updater
        threading.Thread(target=self.update_player_position, daemon=True).start()

    def process_play_packet(self, packet_id, data):
        if packet_id == 0x1F: # Keep Alive
            if len(data) == 8:
                kid = struct.unpack('>q', data)[0]
                self.send_packet(0x0B, struct.pack('>q', kid))
        elif packet_id == 0x41: # Update Health
            self.handle_update_health(data)
        elif packet_id == 0x2F: # Pos Look
            self.handle_pos_look(data)
        elif packet_id == 0x06: # Animation
            pass # Ignore
        elif packet_id == 0x1A: # Disconnect
            self.log("被服务器断开连接")
            self.running = False

    def handle_update_health(self, data):
        try:
            health = struct.unpack('>f', data[0:4])[0]
            self.player_state.health = health
            if health <= 0:
                self.log("玩家死亡，请求复活")
                self.request_respawn = True
        except:
            pass

    def handle_pos_look(self, data):
        try:
            if len(data) < 32: return
            x, y, z = struct.unpack('>ddd', data[0:24])
            yaw, pitch = struct.unpack('>ff', data[24:32])
            
            self.player_state.x = x
            self.player_state.y = y
            self.player_state.z = z
            self.player_state.yaw = yaw
            self.player_state.pitch = pitch
            
            flags = 0
            if len(data) >= 33:
                flags = data[32]
            
            if len(data) > 33:
                # Teleport confirm
                try:
                    teleport_id, _ = read_varint_from_bytes(data[33:])
                    self.send_packet(0x00, pack_varint(teleport_id))
                except:
                    pass
        except:
            pass

    def update_player_position(self):
        velocity_y = 0.0
        gravity = -0.08
        while self.running:
            time.sleep(self.position_update_interval)
            try:
                velocity_y += gravity * self.position_update_interval
                self.player_state.y += velocity_y * self.position_update_interval
                
                if self.player_state.y <= 64.0:
                    self.player_state.y = 64.0
                    velocity_y = 0.0
                    self.player_state.on_ground = True
                else:
                    self.player_state.on_ground = False
                
                data = struct.pack('>dddffB', self.player_state.x, self.player_state.y, self.player_state.z, self.player_state.yaw, self.player_state.pitch, self.player_state.on_ground)
                self.send_packet(0x0E, data)
            except:
                break

    def send_client_status(self, action):
        self.send_packet(0x16, pack_varint(action))

def generate_random_nickname():
    # Generate a random name like Bot_a1b2c3
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{BOT_NAME_PREFIX}{suffix}"

def perform_login(username, password):
    """Performs 4399 -> Netease login and returns (token, entity_id, launcher_version)"""
    if not (C4399Api and NeteaseAuthApi):
        logger.error("缺少登录模块，无法登录")
        return None, None, None

    try:
        logger.info(f"正在为 {username} 进行 4399 登录...")
        c4399 = C4399Api()
        sauth = c4399.login_with_password(username, password)
        
        api = NeteaseAuthApi()
        entity_id, token, auth_otp = api.x19_login_with_sauth(sauth)
        
        launcher_ver = api.game_version if api.game_version else LAUNCHER_VERSION
        
        logger.info(f"登录成功! User: {username}, EntityID: {entity_id}")
        return token, entity_id, launcher_ver
    except Exception as e:
        logger.error(f"登录失败 ({username}): {e}")
        return None, None, None

def main():
    global LAUNCHER_VERSION
    
    bots = []
    
    print(f"开始运行多账号机器人模式，账号数量: {len(ACCOUNTS)}")
    
    # Dictionary to track running bots by username
    # Key: username, Value: BotClient instance
    active_bots = {}

    try:
        while True:
            # Clean up dead threads
            for username in list(active_bots.keys()):
                bot = active_bots[username]
                if not bot.is_alive():
                    print(f"机器人 {username} 已停止运行")
                    del active_bots[username]

            # Check and start bots for configured accounts
            for account_str in ACCOUNTS:
                if ":" not in account_str:
                    continue
                
                username, password = account_str.split(":", 1)
                
                # If bot is already running for this account, skip
                if username in active_bots:
                    continue
                
                print(f"准备启动机器人: {username}")
                
                # Perform login
                token, entity_id, l_ver = perform_login(username, password)
                
                if token and entity_id:
                    # Update global launcher version if needed (though it might vary per login, we use the latest)
                    if l_ver:
                        LAUNCHER_VERSION = l_ver
                        
                    # Create and start bot
                    # Use EntityID as the bot name/profile
                    bot = BotClient(entity_id, token, entity_id)
                    bot.start()
                    active_bots[username] = bot
                    
                    # Stagger logins to avoid rate limits
                    time.sleep(5)
                else:
                    print(f"跳过启动 {username} (登录失败)")
            
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("停止所有机器人...")
        for bot in active_bots.values():
            bot.running = False
        for bot in active_bots.values():
            bot.join()

if __name__ == "__main__":
    main()
