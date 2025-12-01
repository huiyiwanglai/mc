import hashlib
import base64

TOKEN_SALT = "0eGsBkhl"

def get_md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest().lower()

def hex_to_binary(hex_string):
    # Converts each character's ASCII value to an 8-bit binary string
    binary_builder = []
    for char in hex_string:
        # ord(char) gets ASCII value
        # format(..., '08b') converts to 8-bit binary
        binary_builder.append(format(ord(char), '08b'))
    return "".join(binary_builder)

def process_binary_block(secret_bin, http_token):
    # http_token is a bytearray (mutable)
    # secret_bin is a string of '0' and '1'
    
    num_blocks = len(secret_bin) // 8
    for i in range(num_blocks):
        block = secret_bin[i*8 : (i+1)*8]
        xor_buffer = 0
        
        # Parse 8-bit binary string to int
        # The C# code:
        # for (var j = 0; j < block.Length; j++)
        #     if (block[7 - j] == '1')
        #         xorBuffer |= (byte)(1 << j);
        # This is equivalent to int(block, 2)
        xor_buffer = int(block, 2)
        
        http_token[i] ^= xor_buffer

def compute_dynamic_token(request_path, send_body, user_id, user_token):
    if not request_path.startswith('/'):
        request_path = '/' + request_path
        
    # 1. MD5(userToken)
    token_md5 = get_md5(user_token)
    
    # 2. Build Stream
    # stream.Write(Encoding.UTF8.GetBytes(userToken.EncodeMd5().ToLowerInvariant()));
    # stream.Write(sendBody);
    # stream.Write(Encoding.UTF8.GetBytes(TokenSalt));
    # stream.Write(Encoding.UTF8.GetBytes(requestPath));
    
    stream = bytearray()
    stream.extend(token_md5.encode('utf-8'))
    if isinstance(send_body, str):
        stream.extend(send_body.encode('utf-8'))
    else:
        stream.extend(send_body)
    stream.extend(TOKEN_SALT.encode('utf-8'))
    stream.extend(request_path.encode('utf-8'))
    
    # 3. Secret MD5
    secret_md5 = hashlib.md5(stream).hexdigest().lower()
    
    # 4. HexToBinary (ASCII values)
    secret_bin = hex_to_binary(secret_md5)
    
    # 5. Rotate Left 6
    # secretBin = secretBin[6..] + secretBin[..6];
    secret_bin = secret_bin[6:] + secret_bin[:6]
    
    # 6. HttpToken (Bytes of SecretMD5 string)
    http_token = bytearray(secret_md5.encode('utf-8'))
    
    # 7. ProcessBinaryBlock (XOR)
    process_binary_block(secret_bin, http_token)
    
    # 8. Base64 and Format
    # var dynamicToken = (Convert.ToBase64String(httpToken, 0, 12) + "1")
    #     .Replace('+', 'm')
    #     .Replace('/', 'o');
    
    # Take first 12 bytes
    token_part = http_token[:12]
    b64 = base64.b64encode(token_part).decode('utf-8')
    
    dynamic_token = (b64 + "1").replace('+', 'm').replace('/', 'o')
    
    return {
        "user-id": str(user_id),
        "user-token": dynamic_token
    }

if __name__ == "__main__":
    # Test case (if we had one)
    pass
