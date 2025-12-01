import socket
import struct
import zlib
import logging
import hashlib
import json
import time
import base64
from .chacha8 import ChaCha8
from .net import read_frame, write_frame
from .crypto_utils import skip32_encrypt, aes_no_padding_encrypt, rsa_public_decrypt, rsa_private_encrypt
from .netease_keys import NETEASE_PRIVATE_KEY_STR, NETEASE_PUBLIC_KEY_STR

logger = logging.getLogger("NeteaseClient")

TOKEN_KEY = bytes([0xAC, 0x24, 0x9C, 0x69, 0xC7, 0x2C, 0xB3, 0xB4, 0x4E, 0xC0, 0xCC, 0x6C, 0x54, 0x3A, 0x81, 0x95])
SKIP32_KEY = b"SaintSteve" # From UserProfile.cs
MC_VERSION_SALT = bytes([0x01, 0x00, 0x04, 0x80, 0xD2, 0x3E, 0xF7, 0x11, 0x01]) # From YggdrasilGenerator.cs
TCP_SALT = bytes([0x2F, 0x84, 0xAE, 0xA3, 0x99, 0x21, 0x29, 0x26, 0xDA, 0xBF, 0x95, 0xA3, 0xAB, 0xAF, 0x37, 0xE0]) # From YggdrasilGenerator.cs

# Keys from YggdrasilGenerator.cs
PUBLIC_KEY_PEM = base64.b64decode(NETEASE_PUBLIC_KEY_STR)
PRIVATE_KEY_PEM = base64.b64decode(NETEASE_PRIVATE_KEY_STR)

def write_string(s):
    # YggdrasilExtensions.WriteString uses Byte Length
    b = s.encode('utf-8')
    return struct.pack('B', len(b)) + b

def write_long(val):
    # Little Endian
    return struct.pack('<q', val)

def write_int(val):
    # Little Endian
    return struct.pack('<i', val)

def write_bytes(b):
    # Raw Bytes
    return b

def write_short_string(s):
    # Little Endian Short Length
    b = s.encode('utf-8')
    return struct.pack('<H', len(b)) + b

def write_byte_length_string(s):
    # Byte Length
    b = s.encode('utf-8')
    return struct.pack('B', len(b)) + b

def write_short_bytes(b):
    # Little Endian Short Length
    return struct.pack('<H', len(b)) + b

class NeteaseSocketWrapper:
    """
    Wraps the socket to handle Netease encryption transparently.
    Implements a subset of socket methods needed by the MC client.
    """
    def __init__(self, sock, cipher, packer_method, unpacker_method):
        self.sock = sock
        self.cipher = cipher
        self.pack_message = packer_method
        self.unpack_message = unpacker_method
        self.recv_buffer = b""

    def send(self, data):
        # Wrap raw MC data into a Netease Data Packet (Type 0?)
        # Assuming Type 0 is for data transport based on typical tunneling.
        # If data is too large, might need splitting? 
        # For now, send as one packet.
        self.pack_message(0, data)
        return len(data)

    def sendall(self, data):
        self.send(data)

    def recv(self, bufsize):
        # If we have buffered data, return it
        if self.recv_buffer:
            ret = self.recv_buffer[:bufsize]
            self.recv_buffer = self.recv_buffer[bufsize:]
            return ret

        # Otherwise, read a new frame from the wire
        try:
            # This reads a full Netease frame
            msg_type, payload = self.unpack_message()
            
            # We expect Type 0 for data
            if msg_type != 0:
                # Handle other types? KeepAlive?
                # For now, ignore or log
                logger.warning(f"Received non-data packet type: {msg_type}")
                if msg_type == 0xFF: # Disconnect?
                    return b""
                # If it's not data, we might need to read again recursively
                return self.recv(bufsize)
            
            self.recv_buffer += payload
            
            ret = self.recv_buffer[:bufsize]
            self.recv_buffer = self.recv_buffer[bufsize:]
            return ret
            
        except Exception as e:
            # Connection closed or error
            logger.error(f"Error in recv: {e}")
            return b""

    def close(self):
        self.sock.close()
    
    def settimeout(self, t):
        self.sock.settimeout(t)

    def makefile(self, mode='r', buffering=None, **kwargs):
        # Minimal support for makefile if needed (some libs use it)
        return socket.SocketIO(self, mode)


class NeteaseClient:
    def __init__(self, host, port, username, token, launcher_version="1.15.11.28622", game_version="1.12.2"):
        self.host = host
        self.port = port
        self.username = username
        self.token = token
        self.launcher_version = launcher_version
        self.game_version = game_version
        self.sock = None
        self.cipher = None
        self.packer_nonce = b"163 NetEase\n" # 12 bytes
        self.login_seed = None
        self.channel = "netease"
        self.crc_salt = "22AC4B0143EFFC80F2905B267D4D84D3"

    def connect(self):
        print(f"DEBUG: Connecting to {self.host}:{self.port}...")
        logger.info(f"Connecting to {self.host}:{self.port}...")
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=10)
            print("DEBUG: Socket connected. Waiting for handshake...")
            logger.info("Socket connected. Waiting for handshake...")
        except Exception as e:
            print(f"DEBUG: Socket connection failed: {e}")
            logger.error(f"Socket connection failed: {e}")
            raise

        self.sock.settimeout(30)
        
        try:
            # 1. Receive Handshake (Length + Payload)
            # C# InitializeConnection: reads loginSeed (16) + signContent (256) = 272 bytes
            # It seems the initial handshake is RAW, not framed.
            # Wait, C# uses ReadSteamWithInt16Async which reads 2 bytes length first!
            # "using var receive = await stream.ReadSteamWithInt16Async();"
            
            len_bytes = self.sock.recv(2)
            if len(len_bytes) < 2:
                raise ConnectionError("Failed to read handshake length")
            
            # C# ReadSteamWithInt16Async uses Little Endian for length?
            # Extensions/StreamExtensions.cs: 
            # public static async Task<MemoryStream> ReadSteamWithInt16Async(this Stream stream)
            # { var buffer = new byte[2]; await stream.ReadExactlyAsync(buffer); 
            #   var length = BitConverter.ToInt16(buffer); ... }
            # BitConverter endianness depends on system. Usually Little Endian on Windows/Intel.
            # Let's assume Little Endian.
            
            handshake_len = struct.unpack('<H', len_bytes)[0]
            print(f"DEBUG: Handshake length: {handshake_len}")
            
            handshake_data = b''
            while len(handshake_data) < handshake_len:
                chunk = self.sock.recv(handshake_len - len(handshake_data))
                if not chunk:
                    raise ConnectionError("Connection closed during handshake")
                handshake_data += chunk
            
            if len(handshake_data) < 272:
                logger.warning(f"Handshake data length {len(handshake_data)} < 272. Might be incomplete.")
            
            self.login_seed = handshake_data[:16]
            sign_content = handshake_data[16:16+256]
            logger.info(f"Received LoginSeed: {self.login_seed.hex()}")

            # 2. Generate Initialize Packet
            
            # A. Calculate Auth ID (Skip32 Encrypted UserID)
            try:
                user_id = int(self.username)
            except ValueError:
                user_id = 0
            self.user_id = user_id
            
            print(f"DEBUG: Using UserID={user_id} for Skip32 encryption")
            auth_id = skip32_encrypt(user_id, SKIP32_KEY)
            print(f"DEBUG: AuthID (Skip32) = {auth_id}")
            
            # B. Encrypt LoginSeed with AuthToken (AES NoPadding)
            # Token must be XORed with TOKEN_KEY first!
            raw_token = self.token.encode('ascii')
            auth_token = bytearray(len(raw_token))
            for i in range(len(raw_token)):
                auth_token[i] = raw_token[i] ^ TOKEN_KEY[i % len(TOKEN_KEY)]
            auth_token = bytes(auth_token)
            
            encrypted_seed = aes_no_padding_encrypt(self.login_seed, auth_token)
            
            # C. Build Sign
            # self.launcher_version and self.game_version are set in __init__
            # self.channel and self.crc_salt are set in __init__
            
            sign_buffer = bytearray()
            sign_buffer.extend(struct.pack('<I', auth_id))
            sign_buffer.extend(encrypted_seed)
            sign_buffer.extend(self.launcher_version.encode('utf-8'))
            sign_buffer.extend(self.channel.encode('utf-8'))
            sign_buffer.extend(self.crc_salt.encode('utf-8'))
            sign_buffer.extend(self.game_version.encode('utf-8'))
            sign_buffer.extend(MC_VERSION_SALT)
            
            sign_hash = hashlib.sha256(sign_buffer).digest()
            
            # D. Decrypt signContent with Public Key
            client_decrypted = rsa_public_decrypt(PUBLIC_KEY_PEM, sign_content)
            
            if len(client_decrypted) < 19 + 32:
                 raise ValueError("Invalid decrypted client content length")
                 
            client_key = client_decrypted[:19]
            check_sum = client_decrypted[19:19+32]
            
            # Verify CheckSum
            login_seed_hash = hashlib.sha256(self.login_seed).digest()
            if check_sum != login_seed_hash:
                 logger.warning("CheckSum validation failed!")
            else:
                 logger.info("CheckSum verified.")
                 
            # E. Sign (clientKey + sign_hash) with Private Key
            # Data: clientKey + signHash
            sign_data_payload = client_key + sign_hash
            sign_data = rsa_private_encrypt(PRIVATE_KEY_PEM, sign_data_payload)
            
            # F. Construct Packet
            packet = bytearray()
            packet.extend(struct.pack('<I', auth_id))
            packet.extend(encrypted_seed)
            
            # WriteShortString (LauncherVer)
            lv_bytes = self.launcher_version.encode('utf-8')
            packet.extend(struct.pack('>H', len(lv_bytes)))
            packet.extend(lv_bytes)
            
            # WriteByteLengthString (Channel)
            ch_bytes = self.channel.encode('utf-8')
            packet.append(len(ch_bytes))
            packet.extend(ch_bytes)
            
            packet.extend(TCP_SALT)
            
            # WriteShortBytes (SignData)
            packet.extend(struct.pack('<H', len(sign_data)))
            packet.extend(sign_data)
            
            # WriteByteLengthString (GameVer)
            gv_bytes = self.game_version.encode('utf-8')
            packet.append(len(gv_bytes))
            packet.extend(gv_bytes)
            
            packet.extend(MC_VERSION_SALT)
            
            print(f"DEBUG: Packet constructed len={len(packet)}")
            
            # Send Packet (with Length Prefix)
            # C#: message.WriteShort((int)stream.Length);
            # Assuming Little Endian for length prefix too?
            final_packet = struct.pack('<H', len(packet)) + packet
            self.sock.sendall(final_packet)
            print(f"DEBUG: Sent Initialize Packet ({len(final_packet)} bytes)")
            
            # 3. Read Response
            resp_len_bytes = self.sock.recv(2)
            if len(resp_len_bytes) < 2:
                 raise ConnectionError("Failed to read response length")
            resp_len = struct.unpack('<H', resp_len_bytes)[0]
            resp_data = self.sock.recv(resp_len)
            
            if len(resp_data) < 1:
                 raise ConnectionError("Empty response from server")
                 
            status = resp_data[0]
            if status != 0:
                 raise ConnectionError(f"Auth failed with status: {status}")
                 
            print("✅ Auth Server Handshake Successful!")
            
        except Exception as e:
            print(f"DEBUG: Error during handshake: {e}")
            logger.error(f"Error during handshake: {e}")
            raise

        # 4. Setup Encryption
        # Calculate Auth Token: XOR(token_bytes, TokenKey)
        # token is hex string "F3DA..."
        try:
            # Assuming token is the hex string itself as ASCII bytes
            token_ascii = self.token.encode('ascii')
            auth_token = bytearray(len(token_ascii))
            for i in range(len(token_ascii)):
                auth_token[i] = token_ascii[i] ^ TOKEN_KEY[i % len(TOKEN_KEY)]
            auth_token = bytes(auth_token)
        except Exception as e:
            logger.error(f"Error calculating auth token: {e}")
            auth_token = self.token.encode('utf-8') # Fallback

        # Key for Encryption (Client -> Server): AuthToken + LoginSeed
        enc_key = auth_token + self.login_seed
        if len(enc_key) != 32:
             logger.warning(f"Enc Key length {len(enc_key)} != 32. Adjusting...")
             enc_key = enc_key[:32].ljust(32, b'\0')
             
        # Key for Decryption (Server -> Client): LoginSeed + AuthToken
        dec_key = self.login_seed + auth_token
        if len(dec_key) != 32:
             logger.warning(f"Dec Key length {len(dec_key)} != 32. Adjusting...")
             dec_key = dec_key[:32].ljust(32, b'\0')

        logger.info(f"Setting up ChaCha8 Encryption.")
        logger.info(f"Encrypt Key (Hex): {enc_key.hex()}")
        logger.info(f"Decrypt Key (Hex): {dec_key.hex()}")

        self.encryptor = ChaCha8(enc_key, self.packer_nonce)
        self.decryptor = ChaCha8(dec_key, self.packer_nonce)

        
    def join_server(self, server_id):
        # 5. Send JoinServer (Encrypted)
        # Construct complex payload to match YggdrasilGenerator.cs
        
        # Use values from Initialize or Example
        launcher_version = self.launcher_version
        channel = self.channel
        crc_salt = self.crc_salt
        game_version = self.game_version
        
        # Game ID from ExampleConsole
        game_id = "4663909014288106690"
        
        # MD5s from ExampleConsole
        bootstrap_md5 = "684528BF492A84489F825F5599B3E1C6"
        dat_file_md5 = "574033E7E4841D8AC4C14D7FA5E05337"
        
        game_version = self.game_version
        launcher_version = self.launcher_version
        
        mods = []
        prc_check = "[]"
        
        time_val = int(time.time())
        
        # Build Hash Data
        # joinMessage = LauncherVersion + GameVersion + time + CrcSalt + ModInfo + BootstrapMd5 + DatFileMd5 + PrcCheck
        mod_info = json.dumps(mods).replace(" ", "")
        join_message_str = (
            f"{launcher_version}{game_version}{time_val}"
            f"{crc_salt}{mod_info}{bootstrap_md5}"
            f"{dat_file_md5}{prc_check}"
        )
        
        # Combine: utf8(joinMessage) + int(id) + loginSeed
        # id is user_id (int).
        user_id_int = self.user_id
        
        hash_input = join_message_str.encode('utf-8')
        hash_input += struct.pack('<i', user_id_int)
        hash_input += self.login_seed
        
        hash_data = hashlib.sha256(hash_input).digest()
        
        payload = bytearray()
        payload.extend(write_long(int(game_id)))
        payload.extend(write_string(server_id))
        payload.extend(write_string(launcher_version))
        payload.extend(write_string(game_version))
        payload.extend(write_int(time_val))
        payload.extend(write_bytes(hash_data))
        
        payload.extend(write_short_string(mod_info))
        payload.extend(write_short_string(prc_check))
        
        payload.extend(struct.pack('<H', 0)) # WriteShort(0)
        payload.extend(write_byte_length_string(channel))
        
        self._send_encrypted(9, payload)
        
        # 6. Receive JoinServer Response
        msg_type, msg_data = self._recv_encrypted()
        if msg_type != 9:
             raise ConnectionError(f"Unexpected packet type during login: {msg_type}")
        
        if len(msg_data) > 0 and msg_data[0] == 0:
            logger.info("JoinServer successful")
        else:
            raise ConnectionError(f"JoinServer failed: {msg_data.hex()}")
            
        return True

    def _write_string(self, s):
        b = s.encode('utf-8')
        return struct.pack('>H', len(b)) + b

    def _send_encrypted(self, msg_type, data):
        body = bytearray()
        body.append(msg_type)
        body.extend(b'\x88\x88\x88') # Magic
        body.extend(data)
        
        crc = zlib.crc32(body) & 0xFFFFFFFF
        
        to_encrypt = struct.pack('<I', crc) + body
        encrypted = self.encryptor.encrypt(to_encrypt)
        
        write_frame(self.sock, encrypted)

    def _recv_encrypted(self):
        encrypted = read_frame(self.sock)
        print(f"DEBUG: Encrypted (hex): {encrypted.hex()}")
        decrypted = self.decryptor.decrypt(encrypted)
        
        print(f"DEBUG: Decrypted (hex): {decrypted.hex()}")
        if len(decrypted) >= 8:
             print(f"DEBUG: Magic check: {decrypted[5:8].hex()}")
        
        if len(decrypted) < 4:
             raise ValueError("Packet too short")

        stored_crc = struct.unpack('<I', decrypted[:4])[0]
        body = decrypted[4:]
        calc_crc = zlib.crc32(body) & 0xFFFFFFFF
        
        if stored_crc != calc_crc:
            logger.error(f"CRC Mismatch! Stored: {stored_crc:08X}, Calc: {calc_crc:08X}")
            raise ValueError("CRC mismatch")
            
        msg_type = body[0]
        payload = body[4:]
        
        return msg_type, payload

