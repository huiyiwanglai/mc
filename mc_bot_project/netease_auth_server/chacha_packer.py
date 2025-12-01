from typing import Tuple

from Crypto.Cipher import ChaCha20
import zlib


class ChaChaPacker:
    """Python analogue of Codexus.OpenSDK.Cipher.ChaChaPacker + YggdrasilExtensions.PackMessage/UnpackMessage.

    Note: .NET uses ChaCha7539 with configurable rounds (here 8). PyCryptodome's ChaCha20 uses 20 rounds
    internally and a 12-byte nonce. For初版打通流程，我们先保持结构一致，后续如需完全兼容再替换为自实现的ChaCha8。"""

    def __init__(self, key: bytes, nonce: bytes):
        if len(key) != 32:
            # 上层应保证 key = token||loginSeed 为32字节；这里先宽松允许其他长度以便调试
            pass
        # PyCryptodome 要求16/32字节key + 8/12字节nonce；这里直接截断/填充到12字节
        if len(nonce) < 12:
            nonce = nonce.ljust(12, b"\0")
        elif len(nonce) > 12:
            nonce = nonce[:12]
        self.key = key
        self.nonce = nonce

    def _cipher(self) -> ChaCha20.ChaCha20Cipher:
        return ChaCha20.new(key=self.key, nonce=self.nonce)

    def pack_message(self, msg_type: int, data: bytes) -> bytes:
        # 按 C# 逻辑构造明文结构
        msg = bytearray(len(data) + 10)
        total_minus_2 = len(msg) - 2
        msg[0:2] = total_minus_2.to_bytes(2, "little", signed=True)

        msg[6] = msg_type & 0xFF
        msg[7] = 0x88
        msg[8] = 0x88
        msg[9] = 0x88
        msg[10:] = data

        crc = zlib.crc32(bytes(msg[6:])) & 0xFFFFFFFF
        msg[2:6] = crc.to_bytes(4, "big")

        # 从 offset=2 开始做流加密
        cipher = self._cipher()
        msg[2:] = cipher.encrypt(bytes(msg[2:]))
        return bytes(msg)

    def unpack_message(self, packet: bytes) -> Tuple[int, bytes]:
        if len(packet) < 10:
            raise ValueError("packet too short")

        cipher = self._cipher()
        decrypted = bytearray(packet)
        decrypted[2:] = cipher.decrypt(bytes(decrypted[2:]))

        stored_crc = int.from_bytes(decrypted[2:6], "big")
        calc_crc = zlib.crc32(bytes(decrypted[6:])) & 0xFFFFFFFF
        if stored_crc != calc_crc:
            raise ValueError("CRC mismatch in unpack_message")

        msg_type = decrypted[6]
        payload = bytes(decrypted[10:])
        return msg_type, payload
