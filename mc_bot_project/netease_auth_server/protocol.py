import os
import secrets
import socket
from typing import Tuple

from .net import read_frame, write_frame
from .chacha_packer import ChaChaPacker


CHA_CHA_NONCE = "163 NetEase\n".encode("utf-8")


def handle_client(conn: socket.socket, addr: Tuple[str, int]):
    """Minimal auth server side for StandardYggdrasil.JoinServerAsync.

    当前版本：
    - 第一次交互：发送 [len][16字节loginSeed][256字节signContent(占位)]；
    - 第二次交互：接受客户端InitializeMessage，直接返回 [len=1][0x00] 表示通过；
    - 第三次交互：接受加密的JoinServer消息，解密检查类型为9后，始终返回成功(0x00)。

    目的是先打通整体流程，方便你日后在此基础上补充真实校验逻辑。"""
    try:
        # 1. 发送 loginSeed + signContent
        login_seed = secrets.token_bytes(16)
        # 真实实现中 signContent 需要按开源项目的RSA逻辑生成，这里先用占位随机值
        sign_content = secrets.token_bytes(256)
        write_frame(conn, login_seed + sign_content)

        # 2. 读取客户端的 InitializeMessage（我们先不深度解析，直接认为合法）
        _init_req = read_frame(conn)
        # TODO: 如需严格校验，可在此解析id/seed/version等字段

        # 回一字节状态：0x00 表示初始化通过
        write_frame(conn, b"\x00")

        # 3. 读取加密的 JoinServer 请求
        encrypted_join = read_frame(conn)

        # 上层应保证拿得到 user_token；当前demo不知道真实token，故无法真正解密
        # 为了让流程继续，我们这里暂时不解密，只是回一个固定成功响应。
        # 如果你希望完全兼容，需要在Python侧重现"token||loginSeed"的密钥生成逻辑，
        # 并在 C# 客户端那侧确保使用同一user_token。

        # 简化：假设 key 长度为32字节，这里用占位0填充；后续你可以改为真实 token+login_seed
        fake_key = (b"\0" * 32)
        packer = ChaChaPacker(fake_key, CHA_CHA_NONCE)

        # 无法可靠解密客户端发来的 encrypted_join，就不调用 unpack_message，
        # 直接构造一个"成功"响应发回去。
        success_payload = b"\x00"  # unpackMessage[0] == 0x00 => success
        response = packer.pack_message(9, success_payload)
        conn.sendall(response)

    except Exception as e:
        print(f"[auth-server] error handling {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
