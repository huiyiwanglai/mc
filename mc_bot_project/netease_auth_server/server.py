import socket
from typing import Tuple

# 关键：兼容包导入和脚本导入两种方式
try:
    from .protocol import handle_client
except ImportError:
    from protocol import handle_client


def run_auth_server(host: str = "0.0.0.0", port: int = 30000):
    """Run a simple blocking TCP auth server compatible with StandardYggdrasil.JoinServerAsync.

    注意：这是一个教学/调试用的最小实现，仍然缺少：
    - 对 InitializeMessage 的完整解析与签名校验；
    - 对 JoinServer 请求的真实解密与参数校验；
    - 与网易账号体系/租赁服管理后台的实际对接。

    但作为第一步，它可以帮助你验证"协议大致通不通"。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"[auth-server] listening on {host}:{port}")

        while True:
            conn, addr = s.accept()
            print(f"[auth-server] connection from {addr}")
            # 这里采用简单串行处理；如需高并发可以改用多线程/asyncio
            handle_client(conn, addr)


if __name__ == "__main__":
    run_auth_server()
