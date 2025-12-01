import asyncio
import struct
import time
import logging
import os
import zlib
import random
import json
import urllib.request
from functools import partial

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

class BotClient:
    def __init__(self, username, access_token, selected_profile, manager):
        self.username = username
        self.access_token = access_token
        self.selected_profile = selected_profile
        self.manager = manager
        
        self.reader = None
        self.writer = None
        self.running = False
        self.logger = logging.getLogger(f"Bot_{username}")
        
        self.compression_threshold = None
        self.encryptor = None
        self.decryptor = None
        
        self.current_state = 0 # 0:HANDSHAKE, 1:STATUS, 2:LOGIN, 3:PLAY
        self.player_state = utils.PlayerState()
        self.request_respawn = False
        
        self.position_update_interval = config.POSITION_UPDATE_INTERVAL

    def log(self, message, level=logging.INFO):
        self.logger.log(level, message)

    async def run(self):
        self.running = True
        self.log("启动机器人 (Async)")
        await self.connect_and_loop()

    async def connect_and_loop(self):
        reconnect_delay = config.RECONNECT_DELAY

        while self.running:
            try:
                connected = await self.connect_to_server()
                if not connected:
                    self.log(f"连接失败，{reconnect_delay}秒后重试...")
                    await asyncio.sleep(reconnect_delay)
                    continue

                self.encryptor = None
                self.decryptor = None
                
                # 并发运行数据包读取和位置更新
                read_task = asyncio.create_task(self.read_loop())
                update_task = asyncio.create_task(self.update_player_position_loop())
                
                # 等待读取任务结束（通常是连接断开）
                await read_task
                update_task.cancel()
                
            except Exception as e:
                self.log(f"运行时异常: {e}", level=logging.ERROR)
            finally:
                await self.close_connection()
            
            if self.running:
                self.log(f"连接断开，{reconnect_delay}秒后重连...")
                await asyncio.sleep(reconnect_delay)

    async def connect_to_server(self):
        try:
            self.log(f"正在连接到 {config.SERVER_ADDRESS}:{config.SERVER_PORT}")
            # 建立异步连接
            self.reader, self.writer = await asyncio.open_connection(
                config.SERVER_ADDRESS, config.SERVER_PORT
            )
            
            await self.send_handshake_packet()
            self.current_state = 2 # LOGIN
            await self.send_login_start_packet()
            
            return True
        except Exception as e:
            self.log(f"连接建立失败: {e}", level=logging.ERROR)
            return False

    async def close_connection(self):
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass
        self.reader = None
        self.writer = None

    async def read_loop(self):
        try:
            while self.running:
                packet = await self.read_packet()
                if packet is None:
                    break
                
                packet_id, data = packet
                await self.handle_packet(packet_id, data)
                
                if self.request_respawn:
                    self.request_respawn = False
                    await self.send_client_status(0) # Respawn
        except Exception as e:
            self.log(f"读取循环异常: {e}", level=logging.ERROR)

    async def send_packet(self, packet_id, data):
        if not self.writer:
            return False
            
        try:
            packet_data = utils.pack_varint(packet_id) + (data if isinstance(data, (bytes, bytearray)) else bytes(data))
            
            if self.compression_threshold is not None:
                if len(packet_data) >= self.compression_threshold:
                    uncompressed_data = packet_data
                    # zlib压缩是CPU密集型，但在小包情况下直接运行通常没问题
                    # 如果是大包，可以考虑 run_in_executor，但这里为了低延迟直接处理
                    compressed_data = zlib.compress(uncompressed_data)
                    packet_data = utils.pack_varint(len(uncompressed_data)) + compressed_data
                else:
                    packet_data = utils.pack_varint(0) + packet_data
            
            length = utils.pack_varint(len(packet_data))
            packet = length + packet_data
            
            if self.encryptor:
                packet = self.encryptor.update(packet)
            
            self.writer.write(packet)
            await self.writer.drain() # 确保数据发送
            return True
        except Exception as e:
            self.log(f"发送数据包出错: {e}", level=logging.ERROR)
            return False

    async def read_packet(self):
        try:
            # 读取包长
            length = await self.read_varint()
            
            # 读取包体
            packet_data = await self.read_exactly(length)
            
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
            # EOF or Error
            return None

    async def read_exactly(self, n):
        """读取确切的n字节，处理解密"""
        data = bytearray()
        while len(data) < n:
            chunk = await self.reader.read(n - len(data))
            if not chunk:
                raise IOError("连接关闭")
            if self.decryptor:
                chunk = self.decryptor.update(bytes(chunk))
            data.extend(chunk)
        return data

    async def read_varint(self):
        """从流中读取VarInt"""
        num_read = 0
        result = 0
        shift = 0
        while True:
            # 每次读取1字节。StreamReader 有缓冲，所以这很快
            byte_data = await self.reader.read(1)
            if not byte_data:
                raise IOError("连接关闭")
            
            if self.decryptor:
                byte_data = self.decryptor.update(byte_data)
                if not byte_data: # 可能还在缓冲中（对于流式加密不太可能，但为了安全）
                    continue
            
            byte = byte_data[0]
            result |= (byte & 0x7F) << shift
            shift += 7
            num_read += 1
            if num_read > 5:
                raise IOError("VarInt过长")
            if not (byte & 0x80):
                break
        return result

    async def send_handshake_packet(self):
        host_str = config.SERVER_ADDRESS + "\0FML\0"
        data = utils.pack_varint(config.PROTOCOL_VERSION) + utils.pack_string(host_str) + struct.pack('>H', config.SERVER_PORT) + utils.pack_varint(2)
        packet_data = utils.pack_varint(0x00) + data
        
        length = utils.pack_varint(len(packet_data))
        self.writer.write(length + packet_data)
        await self.writer.drain()

    async def send_login_start_packet(self):
        data = utils.pack_string(self.username)
        packet_data = utils.pack_varint(0x00) + data
        length = utils.pack_varint(len(packet_data))
        self.writer.write(length + packet_data)
        await self.writer.drain()

    async def handle_packet(self, packet_id, data):
        if self.current_state == 2: # LOGIN
            if packet_id == 0x01: # Encryption Request
                await self.handle_encryption_request(data)
            elif packet_id == 0x02: # Login Success
                await self.handle_login_success(data)
            elif packet_id == 0x03: # Set Compression
                self.compression_threshold, _ = utils.read_varint_from_bytes(data)
                self.log(f"压缩阈值设置为: {self.compression_threshold}")
        elif self.current_state == 3: # PLAY
            await self.process_play_packet(packet_id, data)

    async def handle_encryption_request(self, data):
        # ... 解析逻辑保持不变 ...
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
            # 在线程池中运行阻塞的网易验证
            await asyncio.get_event_loop().run_in_executor(
                None, self.join_netease_session_sync, server_hash
            )
            
        resp = utils.pack_varint(len(encrypted_shared_secret)) + encrypted_shared_secret + utils.pack_varint(len(encrypted_verify_token)) + encrypted_verify_token
        await self.send_packet(0x01, resp)
        
        cipher = Cipher(algorithms.AES(shared_secret), modes.CFB8(shared_secret), backend=default_backend())
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        self.log("加密已启用")

    def join_netease_session_sync(self, server_hash):
        """同步的网易验证逻辑，将在线程池中运行"""
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

    async def handle_login_success(self, data):
        self.current_state = 3 # PLAY
        self.log("登录成功! 进入游戏状态")

    async def process_play_packet(self, packet_id, data):
        if packet_id == 0x1F: # Keep Alive
            if len(data) == 8:
                kid = struct.unpack('>q', data)[0]
                await self.send_packet(0x0B, struct.pack('>q', kid))
        elif packet_id == 0x41: # Update Health
            self.handle_update_health(data)
        elif packet_id == 0x2F: # Pos Look
            await self.handle_pos_look(data)
        elif packet_id == 0x0F: # Chat Message
            self.handle_chat_message(data)
        elif packet_id == 0x1A: # Disconnect
            self.log("被服务器断开连接")
            self.running = False

    def handle_chat_message(self, data):
        try:
            message_length, index = utils.read_varint_from_bytes(data)
            message_json = data[index:index + message_length].decode('utf-8')
            # 上报给 Manager (非阻塞)
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

    async def handle_pos_look(self, data):
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
                    await self.send_packet(0x00, utils.pack_varint(teleport_id))
                except:
                    pass
        except:
            pass

    async def update_player_position_loop(self):
        velocity_y = 0.0
        gravity = -0.08
        while self.running:
            await asyncio.sleep(self.position_update_interval)
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
                await self.send_packet(0x0E, data)
            except Exception:
                break

    async def send_client_status(self, action):
        await self.send_packet(0x16, utils.pack_varint(action))
