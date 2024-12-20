import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import random
import string

# Shared secret key (must be 16, 24, or 32 bytes long)
raw_key = b'my_secret_key_too_long!'
SECRET_KEY = raw_key[:16]

# Encryption function
def encrypt_message(message, key):
    try:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
        return base64.b64encode(iv + encrypted).decode("utf-8")
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return None

# Decryption function
def decrypt_message(encrypted_message, key):
    try:
        raw_data = base64.b64decode(encrypted_message)
        if len(raw_data) < 16:
            raise ValueError("Message too short for valid IV.")
        iv = raw_data[:16]
        encrypted = raw_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted_data.decode("utf-8")
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return "Invalid message received or decryption error"

# Helper function to generate random username
def generate_random_username(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# Helper function to generate random password
def generate_random_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

async def start_client():
    HOST = "127.0.0.1"
    PORT = 12345
    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
        print(f"[CONNECTED] Connected to the server at {HOST}:{PORT}")

        # Generate random username and password
        username = generate_random_username()
        password = generate_random_password()
        print(f"Generated temporary username: {username}")
        print(f"Generated temporary password: {password}")

        # Prepare authentication message
        auth_message = f"AUTH {username} {password}"
        encrypted_auth_message = encrypt_message(auth_message, SECRET_KEY)

        if not encrypted_auth_message:
            print("[ERROR] Failed to encrypt authentication message.")
            return

        # Send encrypted authentication message to the server
        writer.write(encrypted_auth_message.encode("utf-8"))
        await writer.drain()

        # Receive and decrypt response from the server
        encrypted_response = await reader.read(1024)
        response = decrypt_message(encrypted_response.decode("utf-8"), SECRET_KEY)
        print(f"[SERVER RESPONSE] {response}")

        if "failed" in response:
            print("Authentication failed. Disconnecting...")
            writer.close()
            await writer.wait_closed()
            return

        # If authenticated successfully, interact with the server
        while True:
            command = input("Enter a command ('help' for commands, 'exit' to quit): ").strip()
            if command.lower() == "exit":
                break

            encrypted_command = encrypt_message(command, SECRET_KEY)
            writer.write(encrypted_command.encode("utf-8"))
            await writer.drain()

            encrypted_response = await reader.read(1024)
            response = decrypt_message(encrypted_response.decode("utf-8"), SECRET_KEY)
            print(f"[SERVER RESPONSE] {response}")

        # Close the connection
        writer.close()
        await writer.wait_closed()
        print("[DISCONNECTED] Client connection closed.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    asyncio.run(start_client())
