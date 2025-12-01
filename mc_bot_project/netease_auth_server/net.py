import struct
from typing import Tuple


def read_frame(sock) -> bytes:
    """Blocking read of a length-prefixed frame: [uint16_be length][payload]."""
    header = sock.recv(2)
    if len(header) < 2:
        raise ConnectionError("Connection closed while reading length header")
    (length,) = struct.unpack("<H", header)
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading payload")
        data += chunk
    return data


def write_frame(sock, payload: bytes) -> None:
    """Write a length-prefixed frame: [uint16_be length][payload]."""
    header = struct.pack("<H", len(payload))
    sock.sendall(header + payload)
