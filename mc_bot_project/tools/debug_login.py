import logging
import requests
import sys
import os

# Add parent directory to path to find netease_auth_server
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netease_auth_server.auth_api import NeteaseAuthApi

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def test_login():
    api = NeteaseAuthApi()
    email = "1461929902@qq.com"
    # Use a dummy password or the real one if you want to test authentication.
    # Since I don't have the real password, I expect a 400 or 401/403.
    # If 400, it's a format error. If 401/403, it's auth error (which is progress).
    password = "test_password" 

    print("Initializing device...")
    try:
        device_id = api.initialize_device()
        print(f"Device initialized: {device_id}")
    except Exception as e:
        print(f"Device init failed: {e}")
        return

    print("Attempting login...")
    try:
        user = api.login_with_email(email, password)
        print("Login successful!")
        print(user)
    except requests.exceptions.HTTPError as e:
        print(f"Login failed: {e}")
        print(f"Response content: {e.response.text}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    test_login()
