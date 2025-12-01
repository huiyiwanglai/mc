import socket
import struct
import json
import os
import threading
import time
import logging
import uuid
import argparse
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
import zlib
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import sys
import math
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

# Minecraft协议相关常量
# SERVER_ADDRESS = "127.0.0.1"  # 根据日志提供的服务器地址
# SERVER_PORT = 25565  # 根据日志提供的服务器端口
SERVER_ADDRESS = "117.147.207.62"
SERVER_PORT = 10162
USE_NETEASE_AUTH = True
USERNAME = "ID002"
PROTOCOL_VERSION = 340  # Minecraft 1.12.2的协议版本
MC_VERSION = "1.12.2" # Target Minecraft Version
LAUNCHER_VERSION = "1.15.11.28622" # Default Netease Launcher Version

# Netease Login Credentials (Optional - Set these to use email login)
# NETEASE_EMAIL = "4653107966"
# NETEASE_PASSWORD = "95543912"

# 4399 Login Credentials
C4399_USERNAME = "4653107966" # Please fill in your 4399 username
C4399_PASSWORD = "95543912" # Please fill in your 4399 password
USE_4399_LOGIN = True

# 玩家位置更新间隔（秒）
POSITION_UPDATE_INTERVAL = 0.05

# 玩家初始位置
player_x, player_y, player_z = 100.0, 65.0, 100.0
player_yaw, player_pitch = 0.0, 0.0
on_ground = True

# 运行状态
running = True

# 协议状态常量
STATE_HANDSHAKE = 0
STATE_STATUS = 1
STATE_LOGIN = 2
STATE_PLAY = 3

# 当前协议状态
current_state = STATE_HANDSHAKE
compression_threshold = None

# 是否请求复活（由聊天或包检测触发）
request_respawn = False
# 回放过程中检测到的 packet ids
REPLAY_PACKET_IDS = set()
# 可选的 Mojang session 凭证（从命令行传入）
# WARNING: The user asked to hardcode credentials for testing. These should NOT be committed to public repos.
# For local testing only — token and profile taken from provided log.
ACCESS_TOKEN = "F3DA2CC9407CE7BE312F892231D66E2F"
SELECTED_PROFILE = "0E20F152414C4270B368F832189A72EE"
SKIP_SESSION_JOIN = False
POST_ENCRYPTION_CAPTURE = 0.0
USE_FORGE = False
SESSION_SERVER_URL = None


def parse_launch_log(path):
    """从客户端启动日志里提取 accessToken, selectedProfile, server, port, tweakClass（检测 Forge）"""
    res = {}
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            txt = f.read()
        # 常见启动行包含: [..] [common]: ["--username","ID001","--accessToken","TOKEN",...,"--server","1.2.3.4","--port","10054",...]
        import re
        m = re.search(r'\["--username".*?\]', txt)
        if m:
            arr = eval(m.group(0))
            # arr 是一个列表交替 key/value
            for i in range(0, len(arr)-1, 2):
                k = arr[i].lstrip('-')
                v = arr[i+1]
                res[k] = v
        # 另外直接搜索 --accessToken 或 --selectedProfile 样式
        m2 = re.search(r'--accessToken["\s]*,[\s\"]*([^\",\]]+)', txt)
        if m2:
            res['accessToken'] = m2.group(1)
        # server and port
        m3 = re.search(r'--server["\s]*,[\s\"]*([^\",\]]+)', txt)
        if m3:
            res['server'] = m3.group(1)
        # tweakClass 用于检测 Forge
        if 'FMLTweaker' in txt or 'net.minecraftforge' in txt:
            res['tweakClass'] = 'net.minecraftforge.fml.common.launcher.FMLTweaker'
    except Exception:
        pass
    return res

# Client->Server: Client Status packet id (Play) — used to perform respawn
CLIENT_STATUS_PACKET_ID = 0x16

# 设置主日志，确保使用 UTF-8 编码（显式创建 FileHandler 以兼容不同 Python 版本）
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
log_formatter = logging.Formatter('%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler = logging.FileHandler('minecraft_client.log', encoding='utf-8')
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

# 创建一个新的日志记录器用于聊天消息
message_logger = logging.getLogger('message_logger')
message_logger.propagate = False
message_logger.setLevel(logging.INFO)
message_handler = logging.FileHandler('minecraft_messages.log', encoding='utf-8')
message_handler.setFormatter(logging.Formatter('%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
message_logger.addHandler(message_handler)

# 初始化线程锁
lock = threading.Lock()


class PlayerState:
    """存储玩家当前状态（由服务端数据包更新）"""
    def __init__(self):
        self.health = None
        self.food = None
        self.saturation = None
        self.x = None
        self.y = None
        self.z = None
        self.yaw = None
        self.pitch = None
        self.on_ground = None

    def is_dead(self):
        try:
            return self.health is not None and self.health <= 0
        except Exception:
            return False


# 全局玩家状态实例
player_state = PlayerState()
# 玩家实体ID（由 Join Game 包提供）
player_entity_id = None
respawn_coordinator_active = False


def player_state_monitor(interval=0.25):
    """后台线程，周期性检查玩家状态并在检测到死亡时触发复活重试线程（仅触发一次直到状态恢复）。"""
    global player_state, request_respawn
    was_dead = False
    while running:
        try:
            if player_state.is_dead() and not was_dead:
                log("🔍 监控发现玩家死亡，设置复活请求标志", level=logging.INFO)
                request_respawn = True
                # 启动复活协调器线程（如果尚未启动）
                start_respawn_coordinator()
                was_dead = True
            if not player_state.is_dead() and was_dead:
                # 玩家恢复（重生或其他）
                log("🔍 玩家状态恢复（已重生或回血）", level=logging.INFO)
                was_dead = False
        except Exception as e:
            log(f"⚠️ 玩家状态监控出现异常: {e}", level=logging.ERROR)
        time.sleep(interval)


# 命令文件路径（放在脚本同目录下，避免硬编码绝对路径）
COMMANDS_FILE = os.path.join(os.path.dirname(__file__), 'commands.txt')

def log(message, level=logging.INFO):
    logging.log(level, message)
    print(message)

def send_packet(sock, packet_id, data, encryptor=None, compression_threshold=None):
    # 使用全局锁防止多线程并发写入导致加密流/Socket流错乱
    with lock:
        try:
            # 检查socket是否有效
            if not sock or sock.fileno() == -1:
                log("⚠️ 尝试发送数据到已关闭的连接", level=logging.ERROR)
                return False

            # 保证 packet_data 为 bytes
            packet_data = pack_varint(packet_id) + (data if isinstance(data, (bytes, bytearray)) else bytes(data))

            # 处理压缩
            if compression_threshold is not None:
                if len(packet_data) >= compression_threshold:
                    uncompressed_data = packet_data
                    compressed_data = zlib.compress(uncompressed_data)
                    packet_data = pack_varint(len(uncompressed_data)) + compressed_data
                    log(f"↺ 数据包已压缩：原始长度={len(uncompressed_data)}, 压缩后长度={len(packet_data)}", level=logging.DEBUG)
                else:
                    packet_data = pack_varint(0) + packet_data
                    log(f"↺ 数据包未压缩，长度={len(packet_data)}", level=logging.DEBUG)

            length = pack_varint(len(packet_data))
            packet = length + packet_data
            if encryptor:
                # encryptor.update 返回 bytes
                packet = encryptor.update(packet)
                log(f"🔒 发送前加密数据包：ID={packet_id}, 加密后长度={len(packet)}", level=logging.DEBUG)

            sock.sendall(packet)
            log(f"↑ 数据包已发送：ID={packet_id}, 最终长度={len(packet)}", level=logging.INFO)

            return True
        except socket.error as e:
            log(f"⚠️ 网络错误: {e}", level=logging.ERROR)
            return False
        except Exception as e:
            log(f"⚠️ 发送数据包时出错: {e}", level=logging.ERROR)
            return False

def update_player_position(sock, encryptor):
    global running, player_x, player_y, player_z, player_yaw, player_pitch, on_ground
    velocity_y = 0.0  # 初始垂直速度
    gravity = -0.08  # 简化的重力值
    while running:
        time.sleep(POSITION_UPDATE_INTERVAL)
        try:
            # 更新垂直速度和位置
            velocity_y += gravity * POSITION_UPDATE_INTERVAL
            player_y += velocity_y * POSITION_UPDATE_INTERVAL

            # 简单的地面检测
            if player_y <= 64.0:  # 假设地面高度为Y=64.0
                player_y = 64.0
                velocity_y = 0.0
                on_ground = True
            else:
                on_ground = False

            # 验证坐标和角度为有限数值，避免 NaN/inf 导致服务器断开
            if not all(map(lambda v: isinstance(v, (int, float)) and (not (v != v)) and abs(v) < 1e308, [player_x, player_y, player_z, player_yaw, player_pitch])):
                log(f"⚠️ 无效的位置/角度值，跳过发送：x={player_x},y={player_y},z={player_z},yaw={player_yaw},pitch={player_pitch}", level=logging.WARNING)
            else:
                data = struct.pack('>dddffB', player_x, player_y, player_z, player_yaw, player_pitch, on_ground)
                send_packet(sock, 0x0E, data, encryptor, compression_threshold)
            log(f"↑ 发送玩家位置：x={player_x}, y={player_y}, z={player_z}, on_ground={on_ground}", level=logging.INFO)
        except Exception as e:
            log(f"⚠️ 发送玩家位置时出错: {e}", level=logging.ERROR)
            break

def read_varint(sock, decryptor=None):
    num_read = 0
    result = 0
    shift = 0

    while True:
        byte = sock.recv(1)
        if not byte:
            raise IOError("⚠️ 连接关闭")
        if decryptor:
            # decryptor.update 接受 bytes 并返回 bytes
            dec = decryptor.update(bytes(byte))
            if not dec:
                raise IOError("⚠️ 解密器未返回数据")
            byte = dec[0]
        else:
            byte = byte[0]
        result |= (byte & 0x7F) << shift
        shift += 7
        num_read += 1

        if num_read > 5:
            raise IOError("⚠️ VarInt过长或无效")

        if not (byte & 0x80):
            break

    return result

def read_packet(sock, decryptor=None, compression_threshold=None):
    try:
        length = read_varint(sock, decryptor)
        packet_data = bytearray()
        while len(packet_data) < length:
            chunk = sock.recv(length - len(packet_data))
            if not chunk:
                raise IOError("⚠️ 连接关闭或数据包未能完全接收")
            if decryptor:
                chunk = decryptor.update(bytes(chunk))
                if not chunk:
                    raise IOError("⚠️ 解密器未返回数据（分片）")
            packet_data.extend(chunk)

        index = 0
        if compression_threshold is not None:
            # 先从 packet_data 中读取 VarInt（data length）
            data_length, varint_len = read_varint_from_bytes(packet_data)
            index += varint_len
            if data_length != 0:
                # data_length 表示解压后的长度，压缩数据在 index 之后
                packet_data = zlib.decompress(bytes(packet_data[index:]))
            else:
                packet_data = bytes(packet_data[index:])
        else:
            packet_data = bytes(packet_data)

        packet_id, packet_id_length = read_varint_from_bytes(packet_data)
        data = packet_data[packet_id_length:]

        # 记录解析到的包 id 与数据长度，以及前几十字节的 hex（便于诊断 VarInt/解密/压缩偏移）
        try:
            hex_preview = bytes(data[:32]).hex()
        except Exception:
            hex_preview = str(data)
        log(f"↺ 解析到包: id={packet_id}, len(data)={len(data)}, hex_preview={hex_preview}", level=logging.DEBUG)

        return packet_id, data
    except Exception as e:
        log(f"⚠️ 读取数据包时出错: {e}", level=logging.ERROR)
        return None

def read_varint_from_bytes(data):
    # 支持 bytes, bytearray, memoryview
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

def connect_to_server():
    global current_state, REPLAY_CAPTURE_PATH, REPLAY_PEER, REPLAY_BEFORE_HANDSHAKE, REPLAY_PACKET_IDS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        log(f"🔗 正在连接到 {SERVER_ADDRESS}:{SERVER_PORT}", level=logging.INFO)
        sock.connect((SERVER_ADDRESS, SERVER_PORT))
    except socket.gaierror as e:
        log(f"⚠️ 地址解析失败: {e}", level=logging.ERROR)
        return None
    except Exception as e:
        log(f"⚠️ 连接失败: {e}", level=logging.ERROR)
        return None

    try:
        log("🔗 连接成功", level=logging.INFO)

        # 可选：在握手前回放捕获的包（用于代理/插件初始化流程）
        try:
            if REPLAY_CAPTURE_PATH and REPLAY_BEFORE_HANDSHAKE:
                ids = replay_capture(sock, REPLAY_CAPTURE_PATH, REPLAY_PEER, detect_packet_ids=True)
                if ids:
                    REPLAY_PACKET_IDS.update(ids)
        except Exception as e:
            log(f"⚠️ 回放捕获包（握手前）失败: {e}", level=logging.WARNING)

        # 如果选择只回放捕获文件，但希望继续处理服务器返回以完成握手/登录，则回放后继续
        try:
            if REPLAY_CAPTURE_PATH and REPLAY_ONLY:
                log("🔁 replay-only 模式：开始回放捕获（继续处理服务器响应以完成握手/登录）", level=logging.INFO)
                # 回放原始 client->server 数据（握手前或握手后，根据参数）
                ids = replay_capture(sock, REPLAY_CAPTURE_PATH, REPLAY_PEER, read_response=False, detect_packet_ids=True)
                if ids:
                    REPLAY_PACKET_IDS.update(ids)

                # 短时间读取服务器的即刻响应并交给 handle_packet 继续协议流程（例如 Encryption Request）
                encryptor = None
                decryptor = None
                try:
                        orig_timeout = sock.gettimeout()
                        sock.settimeout(2.0)
                        start_time = time.time()
                        # 临时把状态设置为 LOGIN，以便正确处理服务器发来的 Encryption Request
                        prev_state = current_state
                        try:
                            current_state = STATE_LOGIN
                            # 最多处理若干包或在超时后停止
                            while time.time() - start_time < 2.0:
                                result = read_packet(sock, decryptor, compression_threshold)
                                if result is None:
                                    break
                                packet_id, data = result
                                encryptor, decryptor = handle_packet(sock, packet_id, data, encryptor, decryptor)
                                # 如果已经进入 PLAY 状态或加密已建立，继续让主流程处理后续包
                                if current_state == STATE_PLAY:
                                    break
                        finally:
                            # 恢复原先状态（如果尚未进入 PLAY）
                            current_state = prev_state
                except Exception as e:
                    log(f"⚠️ replay-only 回放后处理服务器响应时出错: {e}", level=logging.WARNING)
                finally:
                    try:
                        sock.settimeout(orig_timeout)
                    except Exception:
                        pass
                # 不在此处直接关闭连接，继续按常规流程发送握手/登录（脚本将尝试完成剩余握手）
        except Exception as e:
            log(f"⚠️ replay-only 回放期间发生错误: {e}", level=logging.ERROR)

        log("🔗 准备发送握手数据包", level=logging.INFO)
        send_handshake_packet(sock)
        current_state = STATE_LOGIN
        log("↑ 握手数据包已发送，准备发送登录启动数据包", level=logging.INFO)
        # 如果回放数据中已经包含 Login Start（packet id 0x00 在登录阶段），则不要重复发送
        try:
            if 0x00 in REPLAY_PACKET_IDS:
                log("🔁 回放中已包含 Login Start，跳过脚本自动发送的 LoginStart", level=logging.INFO)
            else:
                send_login_start_packet(sock)
        except Exception:
            # 保险起见，如果检查失败则发送 LoginStart
            send_login_start_packet(sock)

        # 可选：在握手后回放捕获的包（如果需要）
        try:
            if REPLAY_CAPTURE_PATH and not REPLAY_BEFORE_HANDSHAKE and not REPLAY_ONLY:
                replay_capture(sock, REPLAY_CAPTURE_PATH, REPLAY_PEER)
        except Exception as e:
            log(f"⚠️ 回放捕获包（握手后）失败: {e}", level=logging.WARNING)
    except Exception as e:
        log(f"⚠️ 在连接期间发生错误: {e}", level=logging.ERROR)
        sock.close()
        return None

    return sock

def send_login_start_packet(sock):
    try:
        login_start_data = pack_string(USERNAME)
        send_packet(sock, 0x00, login_start_data)
        log(f"↑ 发送登录启动数据包：用户名={USERNAME}", level=logging.INFO)
    except Exception as e:
        log(f"⚠️ 发送登录启动数据包时出错: {e}", level=logging.ERROR)

def send_handshake_packet(sock):
    try:
        handshake_data = pack_varint(PROTOCOL_VERSION)
        # Append \0FML\0 to server address to indicate Forge client
        # This is standard for modded servers (like Netease)
        host_str = SERVER_ADDRESS + "\0FML\0"
        handshake_data += pack_string(host_str)
        handshake_data += struct.pack('>H', SERVER_PORT)
        handshake_data += pack_varint(2)  # 下一个状态：登录
        send_packet(sock, 0x00, handshake_data)
    except Exception as e:
        log(f"⚠️ 发送握手数据包时出错: {e}", level=logging.ERROR)

def setup_encryption(shared_secret):
    cipher = Cipher(algorithms.AES(shared_secret), modes.CFB8(shared_secret), backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    log(f"🔒 设置加密器和解密器：共享密钥={shared_secret.hex()}", level=logging.DEBUG)
    return encryptor, decryptor

def handle_encryption_request(sock, data):
    try:
        index = 0

        # 读取Server ID
        server_id_length, read_bytes = read_varint_from_bytes(data[index:])
        index += read_bytes
        server_id = data[index:index + server_id_length].decode('utf-8')
        index += server_id_length
        log(f"DEBUG: Received Server ID: '{server_id}'", level=logging.INFO)

        # 读取Public Key
        public_key_length, read_bytes = read_varint_from_bytes(data[index:])
        index += read_bytes
        public_key = data[index:index + public_key_length]
        index += public_key_length

        # 读取Verify Token
        verify_token_length, read_bytes = read_varint_from_bytes(data[index:])
        index += read_bytes
        verify_token = data[index:index + verify_token_length]

        # 生成共享密钥和加密的Verify Token
        shared_secret = os.urandom(16)
        public_key_obj = serialization.load_der_public_key(public_key, backend=default_backend())

        # 保存 public_key DER 到磁盘，便于离线分析（带时间戳以避免覆盖）
        try:
            out_dir = os.path.join(os.path.dirname(__file__), 'replay_responses')
            os.makedirs(out_dir, exist_ok=True)
            ts = int(time.time())
            pk_name = os.path.join(out_dir, f'last_pub_{ts}.der')
            with open(pk_name, 'wb') as pf:
                pf.write(public_key)
            log(f"↩ 保存服务器公钥 DER 到 {pk_name}", level=logging.INFO)
        except Exception:
            pass

        encrypted_shared_secret = public_key_obj.encrypt(shared_secret, padding.PKCS1v15())
        encrypted_verify_token = public_key_obj.encrypt(verify_token, padding.PKCS1v15())

        # 发送Encryption Response
        encryption_response = pack_varint(len(encrypted_shared_secret)) + encrypted_shared_secret
        encryption_response += pack_varint(len(encrypted_verify_token)) + encrypted_verify_token
        # 保存将要发送的 Encryption Response 原始字节（未封包长度/VarInt前的内容）以便离线比对
        try:
            out_dir = os.path.join(os.path.dirname(__file__), 'replay_responses')
            os.makedirs(out_dir, exist_ok=True)
            ts = int(time.time())
            er_fn = os.path.join(out_dir, f'encryption_response_{ts}.bin')
            with open(er_fn, 'wb') as ef:
                ef.write(encryption_response)
            log(f"↩ 保存 Encryption Response 原始字节到 {er_fn}", level=logging.DEBUG)
        except Exception:
            pass

        # --- CRITICAL FIX: Join Auth Server BEFORE sending Encryption Response ---
        # The Game Server checks the session immediately after receiving the response.
        # If we haven't joined yet, it will fail with "authservers_down" or "invalid session".
        if USE_NETEASE_AUTH:
            server_hash = compute_server_hash(server_id, shared_secret, public_key)
            log(f"DEBUG: Computed Server Hash: {server_hash}", level=logging.INFO)
            success, msg = join_netease_session(server_hash)
            if not success:
                log(f"❌ 网易验证失败，终止连接: {msg}", level=logging.ERROR)
                return None
        # -----------------------------------------------------------------------

        send_packet(sock, 0x01, encryption_response)
        log("↑ 发送加密响应数据包", level=logging.INFO)

        # 设置加密器和解密器
        encryptor, decryptor = setup_encryption(shared_secret)
        log("🔒 加密协商完成，已设置加密器和解密器", level=logging.INFO)
        # 返回更多信息以便后续做 session join
        return encryptor, decryptor, shared_secret, server_id, public_key
    except Exception as e:
        log(f"⚠️ 处理加密请求时出错: {e}", level=logging.ERROR)
        return None

def compute_server_hash(server_id, shared_secret, public_key_der):
    # serverHash = SHA1(serverId + shared_secret + public_key)
    m = hashlib.sha1()
    try:
        m.update(server_id.encode('utf-8'))
    except Exception:
        m.update(b'')
    m.update(shared_secret)
    m.update(public_key_der)
    digest = m.digest()
    # Convert to signed BigInteger hex as Java would
    num = int.from_bytes(digest, byteorder='big', signed=True)
    if num < 0:
        return '-' + format(-num, 'x')
    else:
        return format(num, 'x')

def join_session(access_token, selected_profile, server_hash, session_server_url=None, max_retries=5, backoff_base=2.0):
    """POST to Mojang sessionserver to join the server.

    Implements simple retry with exponential backoff. On HTTP or network
    failures the response body (if any) or exception message is saved to
    replay_responses/session_join_error_<ts>.txt under the script directory
    for offline inspection.

    Returns (ok: bool, body_or_error: str).
    """
    out_dir = os.path.join(os.path.dirname(__file__), 'replay_responses')
    os.makedirs(out_dir, exist_ok=True)

    # allow overriding the default Mojang sessionserver URL for testing or custom auth
    if session_server_url:
        url = session_server_url
    else:
        url = 'https://sessionserver.mojang.com/session/minecraft/join'
    payload = json.dumps({
        'accessToken': access_token,
        'selectedProfile': selected_profile,
        'serverId': server_hash
    }).encode('utf-8')

    attempt = 0
    while attempt < max_retries:
        attempt += 1
        # 保存将要发送的 session join 请求体（便于离线比对）
        try:
            ts_req = int(time.time())
            req_out = os.path.join(out_dir, f'session_join_request_{ts_req}_{attempt}.json')
            with open(req_out, 'wb') as rf:
                rf.write(payload)
            log(f"↩ 保存 session join 请求体到 {req_out}", level=logging.DEBUG)
        except Exception:
            pass

        req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body_bytes = resp.read()
                try:
                    body = body_bytes.decode('utf-8')
                except Exception:
                    body = repr(body_bytes)
                log(f"✅ session join 成功 (attempt {attempt})", level=logging.INFO)
                return True, body
        except urllib.error.HTTPError as he:
            # try to read body
            try:
                err_body = he.read()
            except Exception:
                err_body = b''
            ts = int(time.time())
            fname = os.path.join(out_dir, f'session_join_error_{ts}.txt')
            try:
                with open(fname, 'wb') as f:
                    # 写响应的状态/理由与 body，便于离线分析
                    try:
                        header_bytes = str(he.headers).encode('utf-8')
                    except Exception:
                        header_bytes = b''
                    f.write(b'HTTPError: ' + str(he).encode('utf-8') + b'\n')
                    if header_bytes:
                        f.write(b'---HEADERS---\n')
                        f.write(header_bytes + b'\n')
                    if err_body:
                        f.write(b'---BODY---\n')
                        f.write(err_body)
            except Exception:
                pass
            log(f"⚠️ session join HTTPError (attempt {attempt}): {he} -> saved {fname}", level=logging.WARNING)
        except Exception as e:
            ts = int(time.time())
            fname = os.path.join(out_dir, f'session_join_error_{ts}.txt')
            try:
                with open(fname, 'w', encoding='utf-8') as f:
                    f.write('Exception: ' + repr(e))
            except Exception:
                pass
            log(f"⚠️ session join 异常 (attempt {attempt}): {e} -> saved {fname}", level=logging.WARNING)

        # 如果还有重试次数，等待指数退避
        if attempt < max_retries:
            backoff = backoff_base ** attempt
            log(f"⏳ session join 第 {attempt} 次失败，等待 {backoff:.1f}s 后重试", level=logging.INFO)
            time.sleep(backoff)

    return False, 'max_retries_exceeded'

def join_netease_session(server_hash):
    """使用网易协议进行 Session 验证"""
    if not NeteaseClient:
        log("⚠️ NeteaseClient 未加载，无法进行网易验证", level=logging.ERROR)
        return False, "NeteaseClient missing"

    candidates = []

    # 1. 获取 Auth Server 列表
    try:
        import urllib.request
        import json
        import random
        with urllib.request.urlopen("https://x19.update.netease.com/authserver.list", timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data:
                for item in data:
                    ip = item.get('IP') or item.get('ip')
                    port = item.get('Port') or item.get('port')
                    if ip and port:
                        candidates.append((ip, port))
                # Shuffle to distribute load
                random.shuffle(candidates)
                log(f"🔍 获取到 {len(candidates)} 个网易验证服务器", level=logging.INFO)
    except Exception as e:
        log(f"⚠️ 获取网易验证服务器列表失败: {e}", level=logging.WARNING)

    # 2. 添加硬编码的备用服务器 (以防列表服务器不可达)
    # 106.2.44.63 是旧版或某些地区的验证服
    candidates.append(("106.2.44.63", 8095))
    
    if not candidates:
        return False, "No auth servers available"

    # 3. 遍历尝试连接
    last_error = None
    for ip, port in candidates:
        log(f"🔄 尝试连接网易验证服务器: {ip}:{port}", level=logging.INFO)
        try:
            # Use SELECTED_PROFILE (EntityID) as the username for NeteaseClient
            # because NeteaseClient expects an integer ID for Skip32 encryption
            client_username = SELECTED_PROFILE if SELECTED_PROFILE and SELECTED_PROFILE.isdigit() else USERNAME
            log(f"DEBUG: join_netease_session using client_username={client_username}, SELECTED_PROFILE={SELECTED_PROFILE}, LAUNCHER_VERSION={LAUNCHER_VERSION}, MC_VERSION={MC_VERSION}", level=logging.INFO)
            client = NeteaseClient(ip, port, client_username, ACCESS_TOKEN, launcher_version=LAUNCHER_VERSION, game_version=MC_VERSION)
            client.connect() # 握手 + 初始化
            client.join_server(server_hash) # 发送 JoinServer 包
            log(f"✅ 网易 Session 验证成功 ({ip}:{port})", level=logging.INFO)
            return True, "Success"
        except Exception as e:
            log(f"❌ 验证失败 ({ip}:{port}): {e}", level=logging.WARNING)
            last_error = e
            # Continue to next candidate
    
    return False, f"All auth servers failed. Last error: {last_error}"

def handle_packet(sock, packet_id, data, encryptor, decryptor):
    global current_state
    try:
        if current_state == STATE_LOGIN:
            if packet_id == 0x01:  # Encryption Request
                # handle_encryption_request 现在返回更多内容
                res = handle_encryption_request(sock, data)
                if res is None:
                    encryptor = decryptor = None
                else:
                    # unpack returned values
                    try:
                        encryptor, decryptor, shared_secret, server_id, public_key = res
                    except Exception:
                        encryptor, decryptor = res[0], res[1]
                        shared_secret = None
                        server_id = ''
                        public_key = None
                    
                    # 如果启用了网易验证
                    # NOTE: join_netease_session is now called INSIDE handle_encryption_request
                    # to ensure it completes BEFORE sending the Encryption Response.
                    # So we don't need to call it here anymore.
                    if USE_NETEASE_AUTH and shared_secret is not None and public_key is not None:
                         pass 
                    # 否则尝试 Mojang 验证
                    elif ACCESS_TOKEN and SELECTED_PROFILE and shared_secret is not None and public_key is not None:
                        if not SKIP_SESSION_JOIN:
                            try:
                                # 强制在此处发起 session join 并保存结果以便诊断
                                server_hash = compute_server_hash(server_id, shared_secret, public_key)
                                # allow overriding session server URL via global SESSION_SERVER_URL
                                ok, err = join_session(ACCESS_TOKEN, SELECTED_PROFILE, server_hash, session_server_url=SESSION_SERVER_URL, max_retries=5)
                                ts = int(time.time())
                                out_dir = os.path.join(os.path.dirname(__file__), 'replay_responses')
                                os.makedirs(out_dir, exist_ok=True)
                                result_fn = os.path.join(out_dir, f'session_join_result_{ts}.txt')
                                try:
                                    with open(result_fn, 'w', encoding='utf-8') as rf:
                                        rf.write(f'ok={ok}\n')
                                        rf.write(f'result={err}\n')
                                        try:
                                            rf.write(f'server_hash={server_hash}\n')
                                        except Exception:
                                            rf.write('server_hash=<error>\n')

                                        try:
                                            # write a short fingerprint of the server public key for easier comparison with captures
                                            import hashlib as _hashlib
                                            pk_sha1 = _hashlib.sha1(public_key).hexdigest()
                                            rf.write(f'pubkey_sha1={pk_sha1}\n')
                                        except Exception:
                                            rf.write('pubkey_sha1=<error>\n')
                                except Exception:
                                    pass
                                if ok:
                                    log(f"✅ session join 成功（结果已保存到 {result_fn}）", level=logging.INFO)
                                else:
                                    log(f"⚠️ session join 失败（结果已保存到 {result_fn}）: {err}", level=logging.WARNING)
                            except Exception as e:
                                log(f"⚠️ 尝试 session join 时出错: {e}", level=logging.ERROR)
                        else:
                            log("🔁 跳过 session join（由 --skip-session-join 指定）", level=logging.INFO)

                    # 可选：在加密后捕获一段来自服务器的原始字节以供离线分析
                    global POST_ENCRYPTION_CAPTURE
                    if POST_ENCRYPTION_CAPTURE and POST_ENCRYPTION_CAPTURE > 0.0:
                        try:
                            orig_to = sock.gettimeout()
                            sock.settimeout(POST_ENCRYPTION_CAPTURE)
                            chunks = []
                            start_t = time.time()
                            while time.time() - start_t < POST_ENCRYPTION_CAPTURE:
                                try:
                                    c = sock.recv(4096)
                                    if not c:
                                        break
                                    chunks.append(c)
                                except socket.timeout:
                                    break
                                except Exception:
                                    break
                            try:
                                sock.settimeout(orig_to)
                            except Exception:
                                pass
                            if chunks:
                                full = b''.join(chunks)
                                ts = int(time.time())
                                out_dir = os.path.join(os.path.dirname(__file__), 'replay_responses')
                                os.makedirs(out_dir, exist_ok=True)
                                fn = os.path.join(out_dir, f'postenc_{ts}.bin')
                                with open(fn, 'wb') as wf:
                                    wf.write(full)
                                log(f"↩ 已保存加密后来自服务器的原始字节到 {fn}", level=logging.INFO)
                                # 额外：尝试用当前会话的 decryptor 解密并保存解密后的内容，便于分析服务器发送的明文包
                                try:
                                    if decryptor is not None:
                                        try:
                                            dec = decryptor.update(full)
                                        except Exception as _e:
                                            # 有时 decryptor 可能因状态问题抛出异常，记录并继续
                                            dec = None
                                            log(f"⚠️ 解密 post-encryption 数据时出错: {_e}", level=logging.WARNING)
                                        if dec:
                                            fn_dec = os.path.join(out_dir, f'postenc_decrypted_{ts}.bin')
                                            try:
                                                with open(fn_dec, 'wb') as df:
                                                    df.write(dec)
                                                log(f"↩ 已保存解密后的加密后数据到 {fn_dec}", level=logging.INFO)
                                            except Exception:
                                                pass
                                except Exception:
                                    pass
                        except Exception as e:
                            log(f"⚠️ 捕获加密后原始字节时出错: {e}", level=logging.ERROR)
            elif packet_id == 0x02:  # Login Success
                handle_login_success(data, sock, encryptor)
            elif packet_id == 0x03:  # Set Compression
                handle_set_compression(data)
            elif packet_id == 0x00:  # Disconnect (Login)
                # Server sent a disconnect reason (JSON string). Handle and stop.
                try:
                    handle_disconnect(data)
                except Exception as e:
                    log(f"⚠️ 处理登录阶段断开连接时出错: {e}", level=logging.ERROR)
            else:
                log(f"⚠️ 未知的登录阶段数据包ID：{packet_id}", level=logging.WARNING)
        elif current_state == STATE_PLAY:
            # 处理游戏阶段的数据包
            process_play_packet(packet_id, data, sock, encryptor)
        else:
            log(f"⚠️ 未处理的协议状态：{current_state}", level=logging.WARNING)
    except Exception as e:
        log(f"⚠️ 处理数据包时出错: {e}", level=logging.ERROR)
    return encryptor, decryptor

def handle_login_success(data, sock, encryptor):
    global current_state
    current_state = STATE_PLAY
    log("✅ 登录成功，进入游戏状态，启动位置更新线程和命令执行线程", level=logging.INFO)
    # 启动位置更新线程
    threading.Thread(target=update_player_position, args=(sock, encryptor), daemon=True).start()
    # 启动命令执行线程
    threading.Thread(target=execute_commands_from_file, args=(sock, encryptor), daemon=True).start()
    # 启动玩家状态监控线程
    threading.Thread(target=player_state_monitor, daemon=True).start()

def handle_set_compression(data):
    global compression_threshold
    compression_threshold, _ = read_varint_from_bytes(data)
    log(f"🔧 服务器要求压缩，阈值为：{compression_threshold}", level=logging.INFO)

def process_play_packet(packet_id, data, sock, encryptor):
    if packet_id == 0x1F:  # Keep Alive（服务器发送）
        handle_keep_alive(data, sock, encryptor)
    elif packet_id == 0x0F:  # 聊天消息
        handle_chat_message(data)
    elif packet_id == 0x41:  # Update Health (server -> client) in 1.12.2 is 0x41
        handle_update_health(packet_id, data, sock, encryptor)
    elif packet_id == 0x1E:  # Change Game State
        handle_change_game_state(data)
    elif packet_id == 0x2F:  # Player Position and Look (server -> client packet id 0x2F)
        handle_player_position_and_look(data, sock, encryptor)
    elif packet_id == 0x23:  # Join Game (server -> client) is 0x23
        handle_join_game(data)
    elif packet_id == 0x1B:  # Entity Status (server -> client) is 0x1B
        handle_entity_status(data)
    elif packet_id == 0x1A:  # Disconnect（Play） is 0x1A
        handle_disconnect(data)
    elif packet_id == 0x06: # Animation (server -> client)
        # Just log it, don't treat as health
        log(f"↺ 收到动画包 (Animation) ID=0x06, len={len(data)}", level=logging.DEBUG)
    else:
        log(f"↺ 收到游戏阶段的数据包ID：{packet_id}", level=logging.DEBUG)

def handle_keep_alive(data, sock, encryptor):
    try:
        if len(data) != 8:
            log(f"⚠️ 收到的Keep Alive数据长度异常，期望8字节，实际{len(data)}字节", level=logging.ERROR)
            return
        keep_alive_id = struct.unpack('>q', data)[0]  # '>q'表示大端序的Long（8字节）
        # 发送回相同的Keep Alive ID
        keep_alive_data = struct.pack('>q', keep_alive_id)
        send_packet(sock, 0x0B, keep_alive_data, encryptor, compression_threshold)
        log(f"↑ 发送心跳包回应，Keep Alive ID={keep_alive_id}", level=logging.INFO)
    except Exception as e:
        log(f"⚠️ 处理Keep Alive数据包时出错: {e}", level=logging.ERROR)


def handle_join_game(data):
    """处理 Join Game 包，读取玩家实体 ID 并记录。"""
    try:
        global player_entity_id
        # Join Game 包格式（1.12.2）: Entity ID (Int), Gamemode (Unsigned Byte), Dimension (Byte), Difficulty (Unsigned Byte), Max Players (Unsigned Byte), Level Type (String)
        if len(data) < 4:
            log("⚠️ Join Game 数据长度不足，无法读取 Entity ID", level=logging.WARNING)
            return
        player_entity_id = struct.unpack('>i', bytes(data[0:4]))[0]
        log(f"↺ Join Game: 玩家实体ID={player_entity_id}", level=logging.INFO)
    except Exception as e:
        log(f"⚠️ 处理 Join Game 时出错: {e}", level=logging.ERROR)


def handle_entity_status(data):
    """处理 Entity Status 包，若是自身实体并且状态为死亡（3），则触发复活请求标志。"""
    try:
        global player_entity_id, request_respawn
        # Entity Status: Entity ID (Int), Entity Status (Byte)
        if len(data) < 5:
            log("⚠️ Entity Status 数据长度不足", level=logging.WARNING)
            return
        eid = struct.unpack('>i', bytes(data[0:4]))[0]
        status = data[4]
        log(f"↺ Entity Status: eid={eid}, status={status}", level=logging.DEBUG)
        # 状态 3 表示实体死亡（Living Entity dead）
        if eid == player_entity_id and status == 3:
            log("⚠️ 检测到自身实体死亡（Entity Status=3），设置复活请求标志", level=logging.INFO)
            request_respawn = True
    except Exception as e:
        log(f"⚠️ 处理 Entity Status 时出错: {e}", level=logging.ERROR)

def handle_disconnect(data):
    try:
        reason_length, index = read_varint_from_bytes(data)
        reason_json = data[index:index + reason_length].decode('utf-8')
        reason = json.loads(reason_json)
        log(f"⚠️ 被服务器断开连接，原因：{reason}", level=logging.WARNING)
        global running
        running = False
    except Exception as e:
        log(f"⚠️ 处理断开连接数据包时出错: {e}", level=logging.ERROR)
    # 尝试保存原始断开 JSON 到文件，便于离线分析
    try:
        ts = int(time.time())
        out_dir = os.path.join(os.path.dirname(__file__), 'replay_responses')
        os.makedirs(out_dir, exist_ok=True)
        fname = os.path.join(out_dir, f'disconnect_{ts}.json')
        with open(fname, 'w', encoding='utf-8') as wf:
            wf.write(reason_json)
        log(f"↩ 保存断开原因到 {fname}", level=logging.INFO)
    except Exception:
        pass

def handle_chat_message(data):
    try:
        # 读取JSON格式的消息
        message_length, index = read_varint_from_bytes(data)
        message_json = data[index:index + message_length].decode('utf-8')
        index += message_length
        # 读取位置索引（在1.12.2版本中，位置字段是一个Byte）
        position = data[index]
        # 直接记录完整的消息JSON字符串
        message_logger.info(f"[Position {position}] {message_json}")
        print(f"💬 {message_json}")
        # 额外：检测聊天中的死亡提示（一些服务器会发消息提示玩家死亡）
        try:
            # message_json 可能是一个 JSON 文本对象（tellraw），尝试解析出文本内容的简单方式
            parsed = json.loads(message_json)
            text = ''
            # 处理不同的 tellraw 格式
            if isinstance(parsed, dict) and 'text' in parsed:
                text = parsed.get('text', '')
            elif isinstance(parsed, list):
                # 拼接 selector/text 等字段
                for part in parsed:
                    if isinstance(part, dict):
                        text += part.get('text', '')
                    elif isinstance(part, str):
                        text += part
            else:
                text = message_json
        except Exception:
            text = message_json

        # 简单匹配常见死亡文字（英文/中文）
        lowered = text.lower()
        if 'you died' in lowered or 'you are dead' in lowered or '你死' in text:
            log('⚠️ 检测到聊天死亡提示，尝试自动复活', level=logging.INFO)
            # 触发重生（若在 play 状态并且已登录）
            # 需要 sock 与 encryptor，上层调用时无法直接获得，这里仅记录并由主循环/状态触发或者通过外部信号触发
            # 为便于实现，把一个全局标志设置为请求复活
            global request_respawn
            request_respawn = True
    except Exception as e:
        log(f"⚠️ 处理聊天消息时出错: {e}", level=logging.ERROR)

def handle_change_game_state(data):
    try:
        reason = data[0]
        value = struct.unpack('>f', data[1:5])[0]
        log(f"↺ 游戏状态改变，原因代码={reason}, 值={value}", level=logging.INFO)
        # 根据需要处理不同的游戏状态变化
    except Exception as e:
        log(f"⚠️ 处理Change Game State数据包时出错: {e}", level=logging.ERROR)


def send_client_status(sock, encryptor, action=0):
    """发送 Client Status 数据包（用于执行 respawn 等客户端操作）。
    在 Minecraft 1.12.2 中，Client Status (Play) 的格式为：
    - packet id: 0x16（客户端->服务器）
    - action: VarInt（例如 0 表示 perform respawn）
    """
    try:
        data = pack_varint(action)
        # 重试几次以提高在不同时序下的成功率
        attempts = 3
        for i in range(attempts):
            ok = send_packet(sock, CLIENT_STATUS_PACKET_ID, data, encryptor, compression_threshold)
            log(f"↑ 发送 Client Status (action={action}) 尝试 {i+1}/{attempts}, 结果={ok}", level=logging.INFO)
            if ok:
                # 成功发送一次即可
                break
            time.sleep(0.3)
    except Exception as e:
        log(f"⚠️ 发送 Client Status 失败: {e}", level=logging.ERROR)


def respawn_coordinator(sock, encryptor, max_wait=5.0, poll_interval=0.05):
    """协调复活：在检测到死亡时短暂等候，并监听服务器在短时间内的关键包（如 Teleport/Change Game State/Entity Status），然后发送 Client Status 做复活请求并重试。

    这个函数会在独立线程中运行，使用全局标志防止并发。
    """
    global respawn_coordinator_active, running
    try:
        if respawn_coordinator_active:
            return
        respawn_coordinator_active = True
        start_time = time.time()
        saw_teleport_or_respawn = False
        log(f"🔁 复活协调器启动，最长等待 {max_wait}s", level=logging.DEBUG)

        # 在等待期间，我们不会阻塞主接收循环；这里的监听是基于全局日志和状态更新
        # 如果 player_state 在等待期间变为非死亡状态，则取消协调
        while running and time.time() - start_time < max_wait:
            # 如果玩家已被重生（血量恢复或 player_state 非死亡），则退出
            if not player_state.is_dead():
                log("🔁 复活协调器检测到玩家已非死亡状态，取消复活请求", level=logging.INFO)
                respawn_coordinator_active = False
                return
            # 这里只是简单地等待并轮询 player_state 或 player_entity_id 的相关变化
            time.sleep(poll_interval)

        # 超时或等待结束后尝试发送 Client Status（重试若干次）
        attempts = 12
        for i in range(attempts):
            if not running:
                break
            try:
                # 记录重试前的玩家与连接快照
                try:
                    with lock:
                        ps_snapshot = dict(
                            health=player_state.health,
                            food=player_state.food,
                            saturation=player_state.saturation,
                            x=player_state.x,
                            y=player_state.y,
                            z=player_state.z,
                            yaw=player_state.yaw,
                            pitch=player_state.pitch,
                            on_ground=player_state.on_ground,
                        )
                except Exception:
                    ps_snapshot = {}
                sock_info = None
                try:
                    sock_info = getattr(sock, 'fileno', lambda: None)()
                except Exception:
                    sock_info = None

                log(f"🔁 复活协调器发送复活请求 ({i+1}/{attempts}), sock_fileno={sock_info}, player_state={ps_snapshot}", level=logging.INFO)
                send_client_status(sock, encryptor, action=0)
            except Exception as e:
                log(f"⚠️ 复活协调器发送复活请求时异常: {e}", level=logging.ERROR)
            time.sleep(0.25)

    finally:
        respawn_coordinator_active = False
        log("🔁 复活协调器结束", level=logging.DEBUG)


def start_respawn_coordinator():
    """尝试安全地启动复活协调器线程：从当前上下文中查找活跃的 socket/encryptor 并启动线程。

    由于主循环持有 sock 与 encryptor，我们将把启动改为在主循环处执行：
    这里仅设置一个标志，主循环检测到 request_respawn 并会用当前的 sock/encryptor 启动协调器线程。
    """
    # 该函数主要为占位以便 player_state_monitor 能请求启动协调器
    # 真实的启动将在主循环检测 request_respawn 时完成
    return


def handle_update_health(packet_id, data, sock, encryptor):
    """处理 Update Health（服务器->客户端）。1.12.2 中常见结构：
    - health: float
    - food: VarInt
    - foodSaturation: float
    如果 health <= 0 则玩家死亡（或处于死亡状态），可以尝试发送 Client Status(action=0) 来请求重生。
    """
    try:
        # 日志：包含 packet id 与数据长度，便于调试
        log(f"↺ Update Health 收到包ID={packet_id}, 长度={len(data)}", level=logging.DEBUG)
        # 解析 float (4字节) 后面跟 VarInt 和 float（可能包含饥饿与饱和度）
        if len(data) < 4:
            log(f"⚠️ Update Health 数据长度不足 (packet_id={packet_id}, len={len(data)})", level=logging.WARNING)
            return
        health = struct.unpack('>f', data[0:4])[0]
        rest = bytes(data[4:])
        # 尝试读取 food (VarInt)
        food = None
        food_saturation = None
        try:
            food_val, varlen = read_varint_from_bytes(rest)
            food = food_val
            if len(rest) >= varlen + 4:
                food_saturation = struct.unpack('>f', rest[varlen:varlen+4])[0]
        except Exception:
            # 忽略解析失败，只记录
            pass

        log(f"↺ 收到 Update Health: health={health}, food={food}, saturation={food_saturation}, raw={data.hex() if isinstance(data, (bytes,bytearray)) else str(data)}", level=logging.DEBUG)

        # 更新 player_state
        try:
            with lock:
                player_state.health = health
                player_state.food = food
                player_state.saturation = food_saturation
        except Exception:
            pass

        if health <= 0:
            log("⚠️ 检测到血量为零或更低，启动自动复活重试线程", level=logging.INFO)

            def respawn_retry_thread(s, enc, duration=5.0, interval=0.3):
                start = time.time()
                log(f"🔁 自动复活线程启动，将在 {duration}s 内每 {interval}s 尝试发送 Client Status", level=logging.DEBUG)
                while running and time.time() - start < duration:
                    try:
                        send_client_status(s, enc, action=0)
                    except Exception as e:
                        log(f"⚠️ 自动复活线程发送异常: {e}", level=logging.ERROR)
                    time.sleep(interval)
                log("🔁 自动复活线程结束", level=logging.DEBUG)

            threading.Thread(target=respawn_retry_thread, args=(sock, encryptor), daemon=True).start()
    except Exception as e:
        log(f"⚠️ 处理 Update Health 时出错: {e}", level=logging.ERROR)

def handle_player_position_and_look(data, sock, encryptor):
    try:
        # 有些服务器/版本可能不包含 flags/teleport id，这里兼容 len==32 的情况（只有坐标和视角）
        if len(data) < 32:  # 检查数据长度是否足够
            try:
                raw_hex = bytes(data).hex()
            except Exception:
                raw_hex = str(data)
            log(f"⚠️ Position and Look数据包长度不足: {len(data)}字节, raw_hex={raw_hex}", level=logging.ERROR)
            return

        # 读取位置和视角数据（至少32字节）
        x, y, z = struct.unpack('>ddd', bytes(data[0:24]))
        yaw, pitch = struct.unpack('>ff', bytes(data[24:32]))
        flags = None
        # 如果数据长度 >=33，读取 flags（1字节），并在之后尝试读取 teleport id
        if len(data) >= 33:
            flags = data[32]
        
        # 验证坐标与角度是否合理
        def finite(v):
            try:
                return math.isfinite(v)
            except Exception:
                return False

        # 检查坐标是否为有限数且在可接受范围内
        if not (finite(x) and finite(y) and finite(z)):
            log("⚠️ 收到非有限的坐标值，已忽略", level=logging.WARNING)
            return
        if not all(abs(coord) < 30000000 for coord in (x, y, z)):
            log("⚠️ 收到超出世界范围的坐标值，已忽略", level=logging.WARNING)
            return

        # 验证角度（yaw/pitch），pitch 通常在 -90..90，yaw 在 -180..180
        if not (finite(yaw) and finite(pitch)):
            log("⚠️ 收到非有限的角度值，已忽略角度更新", level=logging.WARNING)
            # 只更新坐标，不更新角度
            update_yaw_pitch = False
        else:
            update_yaw_pitch = True

        # 更新玩家位置（并在可能时更新角度）
        global player_x, player_y, player_z, player_yaw, player_pitch
        player_x = max(min(x, 30000000 - 1), -30000000 + 1)
        player_y = max(min(y, 10000), -1000)  # 限制 y 在合理范围
        player_z = max(min(z, 30000000 - 1), -30000000 + 1)
        if update_yaw_pitch:
            # 限制角度范围
            player_yaw = max(min(yaw, 360.0), -360.0)
            player_pitch = max(min(pitch, 90.0), -90.0)
        # 更新全局 player_state
        try:
            with lock:
                player_state.x = player_x
                player_state.y = player_y
                player_state.z = player_z
                player_state.yaw = player_yaw
                player_state.pitch = player_pitch
                # on_ground 字段若在包中存在 flags，可从 flags 推断，但这里使用保守值
                player_state.on_ground = bool(on_ground)
        except Exception:
            pass
        # 如果存在 teleport id，则发送确认包（从 flags 之后读取 VarInt）
        if flags is not None and len(data) > 33:
            offset = 33
            try:
                teleport_id, varint_len = read_varint_from_bytes(bytes(data[offset:]))
                teleport_confirm_data = pack_varint(teleport_id)
                send_packet(sock, 0x00, teleport_confirm_data, encryptor, compression_threshold)
            except Exception:
                log("⚠️ 读取或发送 teleport confirm 时出错（忽略）", level=logging.DEBUG)

        log(f"✅ 更新玩家位置: x={x:.2f}, y={y:.2f}, z={z:.2f}", level=logging.INFO)
        
    except struct.error as e:
        log(f"⚠️ 解析位置数据失败: {e}", level=logging.ERROR)
    except Exception as e:
        log(f"⚠️ 处理位置数据包时出错: {e}", level=logging.ERROR)

def send_chat_message(sock, encryptor, message):
    try:
        chat_data = pack_string(message)
        send_packet(sock, 0x02, chat_data, encryptor, compression_threshold)
        log(f"↑ 发送聊天消息：{message}", level=logging.INFO)
    except Exception as e:
        log(f"⚠️ 发送聊天消息时出错: {e}", level=logging.ERROR)

def execute_commands_from_file(sock, encryptor):
    global running
    try:
        if not os.path.exists(COMMANDS_FILE):
            log(f"⚠️ 命令文件 {COMMANDS_FILE} 不存在", level=logging.ERROR)
            return
        while running:
            with open(COMMANDS_FILE, 'r', encoding='utf-8') as f:
                commands = [line.strip() for line in f if line.strip() != ""]
            if not commands:
                log(f"⚠️ 命令文件 {COMMANDS_FILE} 中没有有效的命令", level=logging.WARNING)
                time.sleep(5)
                continue
            log(f"🔄 从文件中读取到 {len(commands)} 条命令，开始执行", level=logging.INFO)
            for command in commands:
                if not running:
                    break
                send_chat_message(sock, encryptor, command)
                time.sleep(0.1)  # 可根据需要调整命令之间的延迟
            # 防止文件被频繁读取导致忙等待
            time.sleep(1)
    except Exception as e:
        log(f"⚠️ 执行命令时出错: {e}", level=logging.ERROR)

def main():
    global running
    max_reconnect_attempts = 3
    reconnect_delay = 5  # 秒
    global REPLAY_CAPTURE_PATH, REPLAY_PEER, REPLAY_BEFORE_HANDSHAKE, REPLAY_ONLY
    REPLAY_CAPTURE_PATH = None
    REPLAY_PEER = 1
    REPLAY_BEFORE_HANDSHAKE = False
    REPLAY_ONLY = False
    try:
        args = parse_args()
        REPLAY_CAPTURE_PATH = args.replay_capture
        REPLAY_PEER = args.replay_peer
        REPLAY_BEFORE_HANDSHAKE = bool(args.replay_before_handshake)
        REPLAY_ONLY = bool(getattr(args, 'replay_only', False))
        if REPLAY_CAPTURE_PATH:
            log(f"🔁 启用回放：path={REPLAY_CAPTURE_PATH}, peer={REPLAY_PEER}, before_handshake={REPLAY_BEFORE_HANDSHAKE}", level=logging.INFO)
        # 读取可选凭证和调试参数
        global ACCESS_TOKEN, SELECTED_PROFILE, SKIP_SESSION_JOIN, POST_ENCRYPTION_CAPTURE, SERVER_ADDRESS, SERVER_PORT, USE_FORGE, SESSION_SERVER_URL
        # 仅在命令行明确提供凭证时覆盖全局默认值（避免覆盖硬编码的测试凭证为 None）
        at = getattr(args, 'access_token', None)
        sp = getattr(args, 'selected_profile', None)
        if at is not None:
            ACCESS_TOKEN = at
        if sp is not None:
            SELECTED_PROFILE = sp
        SKIP_SESSION_JOIN = bool(getattr(args, 'skip_session_join', False))
        POST_ENCRYPTION_CAPTURE = float(getattr(args, 'post_encryption_capture', 0.0))

        # 可选自定义 session server URL（用于 NetEase 或私有鉴权）
        SESSION_SERVER_URL = getattr(args, 'session_server_url', None)

        # 如果提供了客户端启动日志，尝试解析出 server/port/accessToken/selectedProfile/tweakClass
        launch_log = getattr(args, 'launch_log', None)
        if launch_log:
            parsed = parse_launch_log(launch_log)
            if parsed:
                # server/port
                try:
                    if 'server' in parsed and parsed['server']:
                        SERVER_ADDRESS = parsed['server']
                    if 'port' in parsed and parsed['port']:
                        SERVER_PORT = int(parsed['port'])
                except Exception:
                    pass
                # token/profile
                if 'accessToken' in parsed and parsed['accessToken']:
                    ACCESS_TOKEN = parsed['accessToken']
                if 'uuid' in parsed and parsed['uuid']:
                    SELECTED_PROFILE = parsed['uuid']
                # detect Forge
                if parsed.get('tweakClass') and 'fml' in parsed.get('tweakClass','').lower():
                    USE_FORGE = True
    except SystemExit:
        # argparse 在解析时可能调用 sys.exit；在脚本直接被 import 时忽略
        pass
    
    # --- 4399 Login Logic ---
    if USE_4399_LOGIN and C4399_USERNAME and C4399_PASSWORD:
        log(f"📧 Attempting 4399 Login for {C4399_USERNAME}...", level=logging.INFO)
        if C4399Api and NeteaseAuthApi:
            try:
                c4399 = C4399Api()
                # Note: Captcha handling is not interactive here. If captcha is required, it will fail.
                sauth_str = c4399.login_with_password(C4399_USERNAME, C4399_PASSWORD)
                log("✅ 4399 Login successful.", level=logging.INFO)
                
                api = NeteaseAuthApi()
                entity_id, token, auth_otp = api.x19_login_with_sauth(sauth_str)
                
                if api.game_version:
                    LAUNCHER_VERSION = api.game_version
                    log(f"DEBUG: Updated LAUNCHER_VERSION to {LAUNCHER_VERSION}", level=logging.INFO)
                
                log(f"✅ X19 Login successful via 4399. EntityID: {entity_id}", level=logging.INFO)
                log(f"🔑 Token: {token} (Length: {len(token)})", level=logging.INFO)
                
                aid = auth_otp.get('aid')
                sdkuid = auth_otp.get('sdkuid')
                log(f"DEBUG: AID={aid}, SDKUID={sdkuid}", level=logging.INFO)

                ACCESS_TOKEN = token
                SELECTED_PROFILE = entity_id
                # Try using AID for Auth Server connection
                # SELECTED_PROFILE = aid if aid else entity_id
                # SELECTED_PROFILE = sdkuid if sdkuid else entity_id
                # SELECTED_PROFILE = entity_id
                
                # Update global USERNAME to match the profile we are using
                global USERNAME
                if SELECTED_PROFILE:
                    USERNAME = str(SELECTED_PROFILE)
                    log(f"DEBUG: Updated USERNAME to {USERNAME} (from SELECTED_PROFILE)", level=logging.INFO)
                
                # Try using the full username from unisdk_login_json
                # unisdk_json_str = auth_otp.get('unisdk_login_json')
                # if unisdk_json_str:
                #     try:
                #         # It might be Base64 encoded
                #         import base64
                #         # Add padding if needed
                #         missing_padding = len(unisdk_json_str) % 4
                #         if missing_padding:
                #             unisdk_json_str += '=' * (4 - missing_padding)
                        
                #         log(f"DEBUG: Decoding unisdk_login_json: {unisdk_json_str[:20]}...", level=logging.DEBUG)
                #         decoded_bytes = base64.b64decode(unisdk_json_str)
                #         decoded_str = decoded_bytes.decode('utf-8')
                #         log(f"DEBUG: Decoded unisdk_login_json: {decoded_str[:50]}...", level=logging.DEBUG)
                        
                #         unisdk_data = json.loads(decoded_str)
                        
                #         full_username = unisdk_data.get('username')
                #         if full_username:
                #             USERNAME = full_username
                #             log(f"DEBUG: Updated USERNAME to {USERNAME} (from unisdk_login_json)", level=logging.INFO)
                #     except Exception as e:
                #         log(f"DEBUG: Failed to parse unisdk_login_json: {e}", level=logging.WARNING)
            except Exception as e:
                log(f"❌ 4399 Login failed: {e}", level=logging.ERROR)
        else:
            log("⚠️ C4399Api or NeteaseAuthApi not available (check imports). Skipping 4399 login.", level=logging.WARNING)
    # -------------------------

    sock = None
    for attempt in range(max_reconnect_attempts):
        try:
            sock = connect_to_server()
            if not sock:
                continue
                
            encryptor = None
            decryptor = None
            
            while running:
                result = read_packet(sock, decryptor, compression_threshold)
                if result is None:
                    break
                    
                packet_id, data = result
                encryptor, decryptor = handle_packet(sock, packet_id, data, encryptor, decryptor)
                # 主循环：若收到请求复活的信号，则发送 Client Status (action=0)
                try:
                    global request_respawn
                    if request_respawn:
                        request_respawn = False
                        # 启动复活协调器线程，传入当前 sock 与 encryptor
                        try:
                            threading.Thread(target=respawn_coordinator, args=(sock, encryptor), daemon=True).start()
                        except Exception:
                            # 退回到直接发送（作为后备）
                            send_client_status(sock, encryptor, action=0)
                except Exception as e:
                    log(f"⚠️ 自动复活尝试失败: {e}", level=logging.ERROR)
                
        except ConnectionResetError:
            log("⚠️ 连接被重置，准备重新连接", level=logging.WARNING)
        except KeyboardInterrupt:
            log("🛑 捕获到 KeyboardInterrupt，正在安全退出...", level=logging.INFO)
            running = False
            break
        except Exception as e:
            log(f"⚠️ 严重错误: {e}", level=logging.ERROR)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
                sock = None
                
        if running:
            log(f"💤 等待 {reconnect_delay} 秒后尝试重新连接...", level=logging.INFO)
            time.sleep(reconnect_delay)
        else:
            break
            
    log("👋 客户端已退出", level=logging.INFO)

def self_test():
    """执行一些快速自检，确认基本的二进制读写函数工作正常。"""
    # 测试 pack_varint 与 read_varint_from_bytes
    samples = [0, 1, 127, 128, 255, 300, 2097151]
    for n in samples:
        b = pack_varint(n)
        v, l = read_varint_from_bytes(b)
        if v != n:
            print(f"self_test fail: {n} -> {v}")
            return False
    # 测试 pack_string
    s = "测试字符串"
    sb = pack_string(s)
    length, offset = read_varint_from_bytes(sb)
    extracted = sb[offset:offset + length].decode('utf-8')
    if extracted != s:
        print("self_test fail: string mismatch")
        return False
    print("self_test passed")
    return True

def replay_capture(sock, capture_path, peer_index=1, delay=0.01, read_response=False, response_timeout=2.0, detect_packet_ids=False):
    """从 YAML 捕获文件中读取 packets，并将属于 peer_index 的 data 字段按顺序直接写入 socket（不打包 VarInt 长度），用于在特定测试场景下重放网络负载。

    这只是一个低级回放工具：
    - capture_path: YAML 文件路径
    - peer_index: 要回放的 peer id（对应 YAML 中的 peer 字段）
    - delay: 每个数据片段之间的间隔（秒）
    注意：仅在测试环境使用，回放原始数据可能违反协议/触发服务器保护。
    """
    if not _HAS_YAML:
        log("⚠️ 无法回放捕获包：未安装 PyYAML", level=logging.ERROR)
        return
    try:
        with open(capture_path, 'rb') as f:
            doc = yaml.safe_load(f)
    except Exception as e:
        log(f"⚠️ 读取捕获文件失败: {e}", level=logging.ERROR)
        return

    packets = doc.get('packets', [])
    detected_ids = set()
    for p in packets:
        try:
            if int(p.get('peer', -1)) != int(peer_index):
                continue
            data = p.get('data')
            if not data:
                continue
            # 直接写入原始 bytes
            try:
                sock.sendall(data)
                log(f"↑ 回放数据到 socket: peer={peer_index}, index={p.get('index')}, len={len(data)}", level=logging.DEBUG)
                # 尝试解析 packet id（假设数据以 VarInt length + VarInt id 开始）
                if detect_packet_ids:
                    try:
                        # 解析 VarInt length，然后 packet id
                        plen, plen_len = read_varint_from_bytes(data)
                        pid, pid_len = read_varint_from_bytes(data[plen_len:])
                        detected_ids.add(pid)
                    except Exception:
                        # 忽略解析失败（可能回放数据并非按帧边界）
                        pass
            except Exception as e:
                log(f"⚠️ 回放发送失败: {e}", level=logging.ERROR)
                return
            time.sleep(delay)
        except Exception as e:
            log(f"⚠️ 处理回放条目时出错: {e}", level=logging.ERROR)
            continue

    # 回放完成后可选地读取服务器响应，便于诊断
    if read_response:
        try:
            # 设置短超时以避免长时间阻塞
            orig_timeout = sock.gettimeout()
            sock.settimeout(response_timeout)
            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    # 小的节流，允许继续接收直到超时
                    time.sleep(0.01)
                except socket.timeout:
                    break
                except Exception as e:
                    log(f"⚠️ 回放后读取响应时出错: {e}", level=logging.ERROR)
                    break
            # 恢复原始超时
            try:
                sock.settimeout(orig_timeout)
            except Exception:
                pass

            if chunks:
                full = b''.join(chunks)
                # 保存为 hex 和 utf-8 兼容的预览
                try:
                    preview_text = full.decode('utf-8', errors='replace')
                except Exception:
                    preview_text = ''
                hex_preview = full.hex()
                timestamp = int(time.time())
                out_dir = os.path.join(os.path.dirname(__file__), 'replay_responses')
                try:
                    os.makedirs(out_dir, exist_ok=True)
                except Exception:
                    pass
                filename = os.path.join(out_dir, f'response_{timestamp}.bin')
                try:
                    with open(filename, 'wb') as wf:
                        wf.write(full)
                except Exception as e:
                    log(f"⚠️ 保存回放响应到文件失败: {e}", level=logging.ERROR)

                log(f"↩ 回放后收到服务器响应: {len(full)} 字节, hex_preview(首256字节)={hex_preview[:512]}", level=logging.INFO)
                # 也把较短的 utf-8 预览打印到控制台
                if preview_text:
                    log(f"↩ 响应 utf-8 预览: {preview_text[:1000]}", level=logging.INFO)
            else:
                log("↩ 回放后未收到服务器响应（超时或连接已关闭）", level=logging.INFO)
        except Exception as e:
            log(f"⚠️ 回放后读取服务器响应时出现异常: {e}", level=logging.ERROR)
            
    if detect_packet_ids:
        return detected_ids

def parse_args():
    parser = argparse.ArgumentParser(description='Minecraft-like client with optional capture replay')
    parser.add_argument('--replay-capture', help='YAML 捕获文件路径，用于回放数据包', default=None)
    parser.add_argument('--replay-peer', help='要回放的 peer id（数字）', default=1, type=int)
    parser.add_argument('--replay-before-handshake', help='在发送握手前回放捕获的数据', action='store_true')
    parser.add_argument('--replay-only', help='仅回放捕获的数据然后退出（不发送脚本自己构造的握手/登录）', action='store_true')
    parser.add_argument('--access-token', help='Mojang access token，用于 online-mode 登录', default=None)
    parser.add_argument('--selected-profile', help='Mojang selected profile UUID', default=None)
    parser.add_argument('--skip-session-join', help='跳过向 Mojang session server 发起 join 请求（用于调试）', action='store_true')
    parser.add_argument('--session-server-url', help='Custom session server URL to POST join requests to (overrides Mojang sessionserver)', default=None)
    parser.add_argument('--post-encryption-capture', help='在加密协商完成后捕获来自服务器的原始字节（秒），0 表示不捕获', type=float, default=0.0)
    parser.add_argument('--launch-log', help='path to client launch log to auto-extract accessToken/profile/server/port/tweakClass', default=None)
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--self-test':
        ok = self_test()
        sys.exit(0 if ok else 2)
    try:
        main()
    except KeyboardInterrupt:
        log("🛑 主程序捕获到 KeyboardInterrupt，正在退出", level=logging.INFO)

