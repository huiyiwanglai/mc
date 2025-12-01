import socket
import time

HOST = "117.147.207.62"
PORT = 10162

def check_server():
    print(f"Connecting to {HOST}:{PORT}...")
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        print("Connected!")
        
        s.settimeout(5)
        try:
            print("Waiting for data...")
            data = s.recv(1024)
            print(f"Received {len(data)} bytes: {data.hex()}")
            if len(data) > 2:
                length = int.from_bytes(data[:2], 'big')
                print(f"Possible length prefix: {length}")
        except socket.timeout:
            print("Timed out waiting for data. Server might be waiting for us (Standard MC Protocol?)")
        except Exception as e:
            print(f"Error reading: {e}")
        finally:
            s.close()
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    check_server()
