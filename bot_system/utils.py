import struct
import hashlib
import time

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
