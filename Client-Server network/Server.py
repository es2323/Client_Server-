import asyncio
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import getrandbits
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

# Diffie-Hellman key exchange functions
def generate_dh_keypair():
    private_key = getrandbits(2048)
    public_key = pow(2, private_key, 2**2048 - 1)
    return private_key, public_key

def derive_shared_key(private_key, received_public_key):
    shared_key = pow(received_public_key, private_key, 2**2048 - 1)
    byte_length = (shared_key.bit_length() + 7) // 8
    return shared_key.to_bytes(byte_length, 'big')[:16]

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
    default_devices = [
        ("light", "off", None, None, None),
        ("thermostat", "off", 20, None, None),
        ("fan", "off", None, "low", None),
        ("smart lock", "locked", None, None, None),
        ("camera", "off", None, None, None),
        ("speaker", "off", None, None, None)
    ]
    cursor.executemany("INSERT OR IGNORE INTO devices VALUES (?, ?, ?, ?, ?)", default_devices)
    conn.commit()
    return conn

# Fetch device state
def get_device_state(conn, device_name):
    cursor = conn.cursor()
    cursor.execute("SELECT device_state, temperature, speed, lock_time FROM devices WHERE LOWER(device_name) = LOWER(?)", (device_name,))
    return cursor.fetchone()

# Update device state
def update_device_state_db(conn, device_name, state=None, temperature=None, speed=None, lock_time=None):
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE devices SET device_state = ?, temperature = ?, speed = ?, lock_time = ? WHERE device_name = ?",
        (state, temperature, speed, lock_time, device_name)
    )
    conn.commit()


# Process client commands
async def process_command(conn, command):
    try:
        logging.info(f"Processing command: {command}")

        command = command.lower().strip()
        parts = command.split()

        if len(parts) < 2:
            return "Invalid command format."

        device_name, action = parts[0], parts[1]

        # Multi-word devices like "smart lock"
        if len(parts) > 2 and parts[0] == "smart" and parts[1] == "lock":
            device_name = "smart lock"
            action = parts[2] if len(parts) > 2 else None

        device_state = get_device_state(conn, device_name)
        if device_state is None:
            return f"Device '{device_name}' not found."

        cursor = conn.cursor()
        cursor.execute("SELECT device_state, temperature, speed, lock_time FROM devices WHERE device_name = ?", (device_name,))
        device_state = cursor.fetchone()

        if not device_state:
            return f"Device '{device_name}' not found."

        # Process actions for each device
        if device_name == "light":
                if action in ["on", "off"]:
                    update_device_state_db(conn, device_name, state=action)
                    cursor.execute("UPDATE devices SET device_state = ? WHERE device_name = ?", (action, device_name))
                    conn.commit()
                    return f"Light turned {action}."
                else:
                    return "Invalid light command. Use 'light on' or 'light off'."

        if device_name == "thermostat":
            if action == "get":
                cursor.execute("SELECT device_state FROM devices WHERE device_name = ?", (device_name,))
                device_state = cursor.fetchone()
                if device_state:  # Check if the result is not None
                    return f"Current temperature is {device_state[0]}°C"  # Adjust index based on fetched columns
                else:
                    return "Error: Device state not found for the thermostat."
            elif action == "set" and len(parts) == 3:
                temperature = int(parts[2])
                update_device_state_db(conn, device_name, state="on", temperature=temperature)
                cursor.execute("UPDATE devices SET device_state = 'on' WHERE device_name = ?", (device_name,))
                conn.commit()
                return f"Thermostat set to {temperature}°C"
            else:
                return "Invalid thermostat command. Use 'thermostat get' or 'thermostat set <temp>'."


        if device_name == "fan":
                if action in ["low", "medium", "high"]:
                    update_device_state_db(conn, device_name, state=action)
                    cursor.execute("UPDATE devices SET device_state = 'on', speed = ? WHERE device_name = ?", (action, device_name))
                    conn.commit()
                    return f"Fan set to {action} speed."
                elif action in ["on", "off"]:
                    cursor.execute("UPDATE devices SET device_state = ? WHERE device_name = ?", (action, device_name))
                    conn.commit()
                    return f"Fan turned {action}."
                else:
                    return "Invalid fan command. Use 'fan low/medium/high' or 'fan on/off'."

        if device_name == "smart lock":
                if action in ["locked", "unlocked"]:
                    cursor.execute("UPDATE devices SET device_state = ? WHERE device_name = ?", (action, device_name))
                    conn.commit()
                    return f"Smart lock is now {action}."
                elif action == "lock" and len(parts) >= 3:
                    lock_time = " ".join(parts[2:])
                    cursor.execute("UPDATE devices SET device_state = 'locked', lock_time = ? WHERE device_name = ?", (lock_time, device_name))
                    conn.commit()
                    return f"Smart lock will lock at {lock_time}."
                else:
                    return "Invalid smart lock command. Use 'smart lock locked/unlocked' or 'smart lock lock <time>'."

        if device_name == "camera":
                if action in ["on", "off"]:
                    update_device_state_db(conn, device_name, action)
                    return f"Camera is now {action}."
                else:
                    return "Invalid camera command. Use 'camera on/off'."

        if device_name == "speaker":
                if action in ["on", "off"]:
                    update_device_state_db(conn, device_name, action)
                    return f"Speaker is now {action}."
                elif action == "play" and len(parts) > 2:
                    song = " ".join(parts[2:])
                    return f"Playing '{song}' on the speaker."
                else:
                    return "Invalid speaker command. Use 'speaker on/off' or 'speaker play <song>'."

        elif action in ["on", "off"]:
                update_device_state_db(conn, device_name, action)
                return f"{device_name} is now {action}."
        else:
                return "Invalid command"
    except Exception as e:
            logging.error(f"Error processing command: {e}")
            return f"Error: {str(e)}"

async def handle_client(reader, writer):
    conn = sqlite3.connect("smart_home.db")
    try:
        client_address = writer.get_extra_info('peername')
        logging.info(f"New connection from {client_address}")

        # Receive the client's public key
        client_key_bytes = await reader.read(1024)
        client_public_key = int.from_bytes(client_key_bytes, 'big')

        # Generate the Diffie-Hellman keypair
        private_key, public_key = generate_dh_keypair()

        # Send the server's public key to the client
        public_key_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big')
        writer.write(public_key_bytes)
        await writer.drain()

        # Derive the shared key
        shared_key = derive_shared_key(private_key, client_public_key)
        logging.info(f"[INFO] Shared key established with {client_address}: {shared_key.hex()}")

        # Use the shared key for encryption/decryption
        global SECRET_KEY
        SECRET_KEY = shared_key
        
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
            logging.debug(f"[SERVER] Received command: {command}")

            # Call `process_command` to handle the command
            response = await process_command(conn, command)
            encrypted_response = encrypt_message(response, SECRET_KEY)

            writer.write(encrypted_response.encode("utf-8"))
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
