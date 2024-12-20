import asyncio
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import logging
import random
import string
import os
from argon2 import PasswordHasher

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

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
        logging.error(f"[ENCRYPTION ERROR] {e}")
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
        logging.error(f"[DECRYPTION ERROR] {e}")
        return "Invalid message received or decryption error"

# Helper functions
def hash_password(password):
    return PasswordHasher().hash(password)

def verify_password(stored_password, provided_password):
    try:
        return PasswordHasher().verify(stored_password, provided_password)
    except Exception:
        return False

def generate_random_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def initialize_database():
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_name TEXT PRIMARY KEY,
            device_state TEXT,
            temperature INTEGER,
            speed TEXT,
            lock_time TEXT
        )
    """)
    conn.commit()
    return conn

async def handle_client(reader, writer):
    conn = sqlite3.connect("smart_home.db")
    try:
        encrypted_auth_message = await reader.read(1024)
        auth_message = decrypt_message(encrypted_auth_message.decode("utf-8"), SECRET_KEY)

        if not auth_message or not auth_message.startswith("AUTH"):
            response = encrypt_message("Invalid authentication message", SECRET_KEY)
            writer.write(response.encode("utf-8"))
            await writer.drain()
            return

        _, username, password = auth_message.split()
        cursor = conn.cursor()

        # Check if the username already exists, if not, insert it
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            # Verify password
            if verify_password(result[0], password):
                response = encrypt_message("Authentication successful", SECRET_KEY)
            else:
                response = encrypt_message("Authentication failed", SECRET_KEY)
        else:
            # Insert the generated username and password
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
            conn.commit()
            response = encrypt_message("Authentication successful (user added)", SECRET_KEY)

        writer.write(response.encode("utf-8"))
        await writer.drain()

        if "failed" in response:
            return

        while True:
            encrypted_command = await reader.read(1024)
            if not encrypted_command:
                break

            command = decrypt_message(encrypted_command.decode("utf-8"), SECRET_KEY)
            response = f"Command '{command}' executed."
            writer.write(encrypt_message(response, SECRET_KEY).encode("utf-8"))
            await writer.drain()

    except Exception as e:
        logging.error(f"[SERVER ERROR] {e}")
    finally:
        conn.close()
        writer.close()


async def main():
    conn = initialize_database()
    conn.close()
    server = await asyncio.start_server(handle_client, "127.0.0.1", 12345)
    logging.info("Server is running on 127.0.0.1:12345")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
