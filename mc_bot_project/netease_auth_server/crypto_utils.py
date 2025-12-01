import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

# --- Skip32 Implementation ---
SKIP32_FTABLE = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48,
    0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9, 0xe7,
    0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e,
    0x4e, 0x38, 0x44, 0x28, 0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60,
    0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53, 0x96, 0x84,
    0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7,
    0x16, 0x6a, 0xa2, 0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b,
    0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8, 0x55, 0xb9, 0xda,
    0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b,
    0xd8, 0x90, 0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45,
    0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76, 0x97, 0xfc, 0xb2, 0xc2,
    0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a,
    0x1d, 0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2,
    0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18, 0x89, 0xcb, 0x30, 0x1f, 0x8d,
    0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54,
    0x64, 0x26, 0x7d, 0x03, 0x40, 0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4,
    0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5, 0xad,
    0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e,
    0xff, 0x8c, 0x0e, 0xe2, 0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37,
    0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8, 0x08, 0x77,
    0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3,
    0xa6, 0xbb, 0xac, 0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3,
    0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
]

def _skip32_g(key, k, w):
    g1 = w >> 8
    g2 = w & 0xff
    
    idx1 = (4 * k) % 10
    idx2 = (4 * k + 1) % 10
    idx3 = (4 * k + 2) % 10
    idx4 = (4 * k + 3) % 10
    
    g3 = SKIP32_FTABLE[g2 ^ key[idx1]] ^ g1
    g4 = SKIP32_FTABLE[g3 ^ key[idx2]] ^ g2
    g5 = SKIP32_FTABLE[g4 ^ key[idx3]] ^ g3
    g6 = SKIP32_FTABLE[g5 ^ key[idx4]] ^ g4
    
    return (g5 << 8) + g6

def skip32_encrypt(value, key):
    buf = [
        (value >> 24) & 0xff,
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff
    ]
    
    k = 0
    step = 1
    
    wl = (buf[0] << 8) + buf[1]
    wr = (buf[2] << 8) + buf[3]
    
    i = 0
    while i < 12: # 24 / 2
        wr ^= _skip32_g(key, k, wl) ^ k
        k += step
        wl ^= _skip32_g(key, k, wr) ^ k
        k += step
        i += 1
        
    buf[0] = wr >> 8
    buf[1] = wr & 0xFF
    buf[2] = wl >> 8
    buf[3] = wl & 0xFF
    
    output = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]
    return output

# --- AES No Padding ---
def aes_no_padding_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

# --- RSA Helpers ---
def rsa_decrypt_with_public_key(public_key_der, data):
    """
    Decrypts data using the Public Key (effectively verifying a signature/recovering data).
    Assumes PKCS#1 v1.5 padding (Block Type 1).
    """
    key = RSA.import_key(public_key_der)
    n = key.n
    e = key.e
    c = bytes_to_long(data)
    m = pow(c, e, n)
    
    m_bytes = long_to_bytes(m, (n.bit_length() + 7) // 8)
    
    # Remove PKCS1 v1.5 padding: 00 01 FF ... FF 00 [DATA]
    # Note: long_to_bytes might strip leading nulls, so we pad to block size
    if len(m_bytes) < (n.bit_length() + 7) // 8:
        m_bytes = b'\x00' * ((n.bit_length() + 7) // 8 - len(m_bytes)) + m_bytes
        
    if m_bytes[0:2] != b'\x00\x01':
        raise ValueError("Invalid PKCS1 padding header")
        
    idx = m_bytes.find(b'\x00', 2)
    if idx == -1:
        raise ValueError("Invalid PKCS1 padding: no separator")
        
    return m_bytes[idx+1:]

def rsa_public_decrypt(public_key_der, data):
    """
    Decrypts data using the Public Key (effectively verifying a signature/recovering data).
    Assumes PKCS#1 v1.5 padding (Block Type 1).
    """
    key = RSA.import_key(public_key_der)
    n = key.n
    e = key.e
    c = bytes_to_long(data)
    m = pow(c, e, n)
    
    m_bytes = long_to_bytes(m, (n.bit_length() + 7) // 8)
    
    # Remove PKCS1 v1.5 padding: 00 01 FF ... FF 00 [DATA]
    if len(m_bytes) < (n.bit_length() + 7) // 8:
        m_bytes = b'\x00' * ((n.bit_length() + 7) // 8 - len(m_bytes)) + m_bytes
        
    if m_bytes[0:2] != b'\x00\x01':
        # Sometimes it might be Block Type 2 if it was encrypted with Private Key? 
        # But usually Private Key encryption (Signature) uses Type 1.
        # Let's allow Type 2 just in case, but warn.
        if m_bytes[0:2] == b'\x00\x02':
             pass # OK
        else:
             raise ValueError(f"Invalid PKCS1 padding header: {m_bytes[0:2].hex()}")
        
    idx = m_bytes.find(b'\x00', 2)
    if idx == -1:
        raise ValueError("Invalid PKCS1 padding: no separator")
        
    return m_bytes[idx+1:]

def rsa_private_encrypt(private_key_der, data):
    """
    Encrypts data using the Private Key (Signing).
    Uses PKCS#1 v1.5 padding (Block Type 1).
    """
    key = RSA.import_key(private_key_der)
    n = key.n
    d = key.d
    k = (n.bit_length() + 7) // 8
    
    if len(data) > k - 11:
        raise ValueError("Data too long for RSA key")
        
    # PKCS#1 v1.5 Block Type 1 Padding
    # 00 01 FF ... FF 00 DATA
    ps_len = k - 3 - len(data)
    padding = b'\xff' * ps_len
    block = b'\x00\x01' + padding + b'\x00' + data
    
    m = bytes_to_long(block)
    c = pow(m, d, n)
    c_bytes = long_to_bytes(c, k)
    
    return c_bytes

    if len(m_bytes) < (n.bit_length() + 7) // 8:
        m_bytes = b'\x00' * ((n.bit_length() + 7) // 8 - len(m_bytes)) + m_bytes

    # Look for 00 separator after 00 01
    # We expect 00 01 ...
    if m_bytes[0:2] == b'\x00\x01':
        try:
            idx = m_bytes.find(b'\x00', 2)
            if idx != -1:
                return m_bytes[idx+1:]
        except:
            pass
    # Fallback: just search for 00 separator
    try:
        idx = m_bytes.find(b'\x00', 2)
        if idx != -1:
            return m_bytes[idx+1:]
    except:
        pass
        
    return m_bytes

def rsa_sign_pkcs1(private_key_der, data):
    """
    Encrypts data using the Private Key (Signing) with PKCS#1 v1.5 padding (Block Type 1).
    """
    key = RSA.import_key(private_key_der)
    mod_len = (key.n.bit_length() + 7) // 8
    
    # Construct padding: 00 01 FF ... FF 00 DATA
    pad_len = mod_len - len(data) - 3
    if pad_len < 8:
        raise ValueError("Data too long for RSA key")
        
    padding = b'\x00\x01' + (b'\xff' * pad_len) + b'\x00' + data
    
    m_int = bytes_to_long(padding)
    s_int = pow(m_int, key.d, key.n)
    s_bytes = long_to_bytes(s_int, mod_len)
    return s_bytes

