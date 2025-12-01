import socket
import struct
import threading
import time
import logging
import os
import zlib
import random
import json
import urllib.request

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import config
from . import utils

try:
    from netease_auth_server.client import NeteaseClient
except ImportError:
    NeteaseClient = None

class BotClient(threading.Thread):
    def __init__(self, username, access_token, selected_profile, manager):
        super().__init__()
        self.username = username # 这里通常是 EntityID
        self.access_token = access_token
        self.selected_profile = selected_profile
        self.manager = manager # 引用 Manager 以便上报事件
        
        self.sock = None
        self.running = True
        self.lock = threading.Lock()
        self.logger = logging.getLogger(f"Bot_{username}")
        
        self.compression_threshold = None
        self.encryptor = None
        self.decryptor = None
        
        self.current_state = 0 # STATE_HANDSHAKE
        self.player_state = utils.PlayerState()
        self.request_respawn = False
        
        self.position_update_interval = config.POSITION_UPDATE_INTERVAL
        
        # Buffer for socket receiving
        self.recv_buffer = bytearray()

    def log(self, message, level=logging.INFO):
        self.logger.log(level, message)

    def run(self):
        self.log("启动机器人线程")
        self.connect_and_loop()

    def connect_and_loop(self):
        max_reconnect_attempts = 9999
        reconnect_delay = config.RECONNECT_DELAY

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
                self.recv_buffer.clear()
                
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
            self.log(f"正在连接到 {config.SERVER_ADDRESS}:{config.SERVER_PORT}")
            sock.connect((config.SERVER_ADDRESS, config.SERVER_PORT))
            
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
                
                packet_data = utils.pack_varint(packet_id) + (data if isinstance(data, (bytes, bytearray)) else bytes(data))
                
                if self.compression_threshold is not None:
                    if len(packet_data) >= self.compression_threshold:
                        uncompressed_data = packet_data
                        compressed_data = zlib.compress(uncompressed_data)
                        packet_data = utils.pack_varint(len(uncompressed_data)) + compressed_data
                    else:
                        packet_data = utils.pack_varint(0) + packet_data
                
                length = utils.pack_varint(len(packet_data))
                packet = length + packet_data
                
                if self.encryptor:
                    packet = self.encryptor.update(packet)
                
                self.sock.sendall(packet)
                return True
            except Exception as e:
                self.log(f"发送数据包出错: {e}", level=logging.ERROR)
                return False

    def _ensure_buffer(self, min_length):
        while len(self.recv_buffer) < min_length:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise IOError("连接关闭")
            if self.decryptor:
                chunk = self.decryptor.update(bytes(chunk))
            self.recv_buffer.extend(chunk)

    def read_packet(self):
        try:
            length = self.read_varint()
            self._ensure_buffer(length)
            
            packet_data = self.recv_buffer[:length]
            del self.recv_buffer[:length]
            
            index = 0
            if self.compression_threshold is not None:
                data_length, varint_len = utils.read_varint_from_bytes(packet_data)
                index += varint_len
                if data_length != 0:
                    packet_data = zlib.decompress(bytes(packet_data[index:]))
                else:
                    packet_data = bytes(packet_data[index:])
            else:
                packet_data = bytes(packet_data)
            
            packet_id, packet_id_length = utils.read_varint_from_bytes(packet_data)
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
            if len(self.recv_buffer) == 0:
                self._ensure_buffer(1)
            
            byte = self.recv_buffer[0]
            del self.recv_buffer[0]
            
            result |= (byte & 0x7F) << shift
            shift += 7
            num_read += 1
            if num_read > 5:
                raise IOError("VarInt过长")
            if not (byte & 0x80):
                break
        return result

    def send_handshake_packet(self, sock):
        host_str = config.SERVER_ADDRESS + "\0FML\0"
        data = utils.pack_varint(config.PROTOCOL_VERSION) + utils.pack_string(host_str) + struct.pack('>H', config.SERVER_PORT) + utils.pack_varint(2)
        packet_data = utils.pack_varint(0x00) + data
        length = utils.pack_varint(len(packet_data))
        sock.sendall(length + packet_data)

    def send_login_start_packet(self, sock):
        data = utils.pack_string(self.username)
        packet_data = utils.pack_varint(0x00) + data
        length = utils.pack_varint(len(packet_data))
        sock.sendall(length + packet_data)

    def handle_packet(self, packet_id, data):
        if self.current_state == 2: # LOGIN
            if packet_id == 0x01: # Encryption Request
                self.handle_encryption_request(data)
            elif packet_id == 0x02: # Login Success
                self.handle_login_success(data)
            elif packet_id == 0x03: # Set Compression
                self.compression_threshold, _ = utils.read_varint_from_bytes(data)
                self.log(f"压缩阈值设置为: {self.compression_threshold}")
        elif self.current_state == 3: # PLAY
            self.process_play_packet(packet_id, data)

    def handle_encryption_request(self, data):
        index = 0
        server_id_len, l = utils.read_varint_from_bytes(data)
        index += l
        server_id = data[index:index+server_id_len].decode('utf-8')
        index += server_id_len
        
        pk_len, l = utils.read_varint_from_bytes(data[index:])
        index += l
        public_key = data[index:index+pk_len]
        index += pk_len
        
        vt_len, l = utils.read_varint_from_bytes(data[index:])
        index += l
        verify_token = data[index:index+vt_len]
        
        shared_secret = os.urandom(16)
        public_key_obj = serialization.load_der_public_key(public_key, backend=default_backend())
        
        encrypted_shared_secret = public_key_obj.encrypt(shared_secret, padding.PKCS1v15())
        encrypted_verify_token = public_key_obj.encrypt(verify_token, padding.PKCS1v15())
        
        if config.USE_NETEASE_AUTH:
            server_hash = utils.compute_server_hash(server_id, shared_secret, public_key)
            self.join_netease_session(server_hash)
            
        resp = utils.pack_varint(len(encrypted_shared_secret)) + encrypted_shared_secret + utils.pack_varint(len(encrypted_verify_token)) + encrypted_verify_token
        self.send_packet(0x01, resp)
        
        cipher = Cipher(algorithms.AES(shared_secret), modes.CFB8(shared_secret), backend=default_backend())
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        self.log("加密已启用")

    def join_netease_session(self, server_hash):
        if not NeteaseClient:
            return
        
        candidates = [("106.2.44.63", 8095)]
        try:
            with urllib.request.urlopen("https://x19.update.netease.com/authserver.list", timeout=5) as r:
                d = json.loads(r.read().decode('utf-8'))
                for i in d:
                    candidates.append((i.get('IP') or i.get('ip'), i.get('Port') or i.get('port')))
        except:
            pass
            
        random.shuffle(candidates)
        
        client_username = self.selected_profile if self.selected_profile and self.selected_profile.isdigit() else self.username
        
        for ip, port in candidates:
            try:
                client = NeteaseClient(ip, port, client_username, self.access_token, launcher_version=config.LAUNCHER_VERSION, game_version=config.MC_VERSION)
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
        elif packet_id == 0x0F: # Chat Message
            self.handle_chat_message(data)
        elif packet_id == 0x1A: # Disconnect
            self.log("被服务器断开连接")
            self.running = False

    def handle_chat_message(self, data):
        try:
            message_length, index = utils.read_varint_from_bytes(data)
            message_json = data[index:index + message_length].decode('utf-8')
            # 上报给 Manager 进行去重处理
            self.manager.on_chat_message(self, message_json)
        except Exception as e:
            self.log(f"解析聊天消息失败: {e}", level=logging.ERROR)

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
            
            if len(data) > 33:
                try:
                    teleport_id, _ = utils.read_varint_from_bytes(data[33:])
                    self.send_packet(0x00, utils.pack_varint(teleport_id))
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
        self.send_packet(0x16, utils.pack_varint(action))
