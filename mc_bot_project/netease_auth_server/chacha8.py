import struct

def rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

class ChaCha8:
    """
    Pure Python implementation of ChaCha20 with 8 rounds (ChaCha8).
    Compatible with RFC 7539 (96-bit nonce, 32-bit counter).
    """
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")

        self.state = [0] * 16
        # Constants "expand 32-byte k"
        self.state[0] = 0x61707865
        self.state[1] = 0x3320646e
        self.state[2] = 0x79622d32
        self.state[3] = 0x6b206574
        
        # Key
        k = struct.unpack('<8I', key)
        self.state[4:12] = k
        
        # Counter (position 12)
        self.state[12] = counter
        
        # Nonce (positions 13, 14, 15)
        n = struct.unpack('<3I', nonce)
        self.state[13:16] = n
        
        self.keystream_buffer = bytearray()

    def _quarter_round(self, x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c], 7)

    def _generate_block(self):
        x = list(self.state)
        # 8 rounds = 4 iterations of (column rounds + diagonal rounds)
        for _ in range(4):
            # Column rounds
            self._quarter_round(x, 0, 4, 8, 12)
            self._quarter_round(x, 1, 5, 9, 13)
            self._quarter_round(x, 2, 6, 10, 14)
            self._quarter_round(x, 3, 7, 11, 15)
            # Diagonal rounds
            self._quarter_round(x, 0, 5, 10, 15)
            self._quarter_round(x, 1, 6, 11, 12)
            self._quarter_round(x, 2, 7, 8, 13)
            self._quarter_round(x, 3, 4, 9, 14)
            
        block = bytearray(64)
        for i in range(16):
            val = (x[i] + self.state[i]) & 0xFFFFFFFF
            block[i*4:(i+1)*4] = struct.pack('<I', val)
            
        self.state[12] = (self.state[12] + 1) & 0xFFFFFFFF
        return block

    def encrypt(self, data: bytes) -> bytes:
        data = bytearray(data)
        output = bytearray(len(data))
        
        for i in range(len(data)):
            if not self.keystream_buffer:
                self.keystream_buffer = self._generate_block()
            
            output[i] = data[i] ^ self.keystream_buffer.pop(0)
            
        return bytes(output)

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)
