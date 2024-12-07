import asyncio
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from argon2 import PasswordHasher
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)

# Shared secret key (must be 16, 24, or 32 bytes long)
raw_key = b'my_secret_key_too_long!'
SECRET_KEY = raw_key[:16]

# Alter the schema if needed (add missing columns)
def alter_devices_table():
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE devices ADD COLUMN speed TEXT")
        cursor.execute("ALTER TABLE devices ADD COLUMN lock_time TEXT")
    except sqlite3.OperationalError as e:
        logging.info(f"Schema already up-to-date or error: {e}")
    conn.commit()
    conn.close()

# Initialize SQLite Database
def init_database():
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    logging.info("Initializing database...")

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)

    # Create devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            name TEXT PRIMARY KEY,
            state TEXT,
            temperature INTEGER,
            speed TEXT,
            lock_time TEXT
        )
    """)

    # Alter schema to match new requirements
    alter_devices_table()

    logging.info("Tables 'users' and 'devices' created or verified.")

    # Insert default devices
    default_devices = [
        ("light", "off", None, None, None),
        ("thermostat", "off", 20, None, None),
        ("fan", "off", None, "low", None),
        ("smart lock", "locked", None, None, None),
        ("camera", "off", None, None, None),
        ("speaker", "off", None, None, None)
    ]
    cursor.executemany("INSERT OR IGNORE INTO devices VALUES (?, ?, ?, ?, ?)", default_devices)

    # Insert default user
    default_users = [
        ("testuser", hash_password("testpassword"))
    ]
    cursor.executemany("INSERT OR IGNORE INTO users VALUES (?, ?)", default_users)

    conn.commit()
    conn.close()
    logging.info("Default devices and users inserted.")

# Hash a password using Argon2
def hash_password(password):
    ph = PasswordHasher()
    return ph.hash(password)

# Verify a password using Argon2
def verify_password(stored_password, provided_password):
    ph = PasswordHasher()
    try:
        return ph.verify(stored_password, provided_password)
    except Exception:
        return False

# Authenticate a user
def authenticate_user(username, password):
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_password = result[0]
        return verify_password(stored_password, password)
    return False

# Fetch device state
def get_device_state(device_name):
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute("SELECT state, temperature, speed, lock_time FROM devices WHERE LOWER(name) = LOWER(?)", (device_name,))
    result = cursor.fetchone()
    conn.close()
    return result

# Update device state
def update_device_state_db(device_name, state=None, temperature=None, speed=None, lock_time=None):
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE devices SET state = ?, temperature = ?, speed = ?, lock_time = ? WHERE name = ?",
        (state, temperature, speed, lock_time, device_name)
    )
    conn.commit()
    conn.close()

# Decrypt message
def decrypt_message(encrypted_message, key):
    raw_data = base64.b64decode(encrypted_message)
    iv = raw_data[:16]
    encrypted = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode('utf-8')

# Encrypt message
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted).decode('utf-8')

# Process client commands
async def process_command(command):
    try:
        logging.info(f"Received command: {command}")

        command = command.lower()
        parts = command.split(' ')

        # Handle multi-word devices like "smart lock"
        if len(parts) > 2 and parts[0] == 'smart' and parts[1] == 'lock':
            device_name = 'smart lock'
            action = parts[2] if len(parts) > 2 else None
        else:
            device_name = parts[0]
            action = parts[1] if len(parts) > 1 else None

        logging.info(f"Device name: {device_name}, Action: {action}")

        # Fetch device state
        device_state = get_device_state(device_name)
        if device_state is None:
            return f"Device '{device_name}' not found"

        # Process actions for each device
        if device_name == "thermostat":
            if action == "get":
                return f"Current temperature is {device_state[1]}°C"
            elif action == "set" and len(parts) == 3:
                temperature = int(parts[2])
                update_device_state_db(device_name, "on", temperature)
                return f"Thermostat set to {temperature}°C"
            else:
                return "Invalid thermostat command. Use 'thermostat get' or 'thermostat set <temp>'."

        elif device_name == "fan":
            if action in ["low", "medium", "high"]:
                update_device_state_db(device_name, "on", None, action)
                return f"Fan set to {action} speed."
            elif action in ["on", "off"]:
                update_device_state_db(device_name, action)
                return f"Fan is now {action}."
            else:
                return "Invalid fan command. Use 'fan low/medium/high' or 'fan on/off'."

        elif device_name == "smart lock":
            if action in ["locked", "unlocked"]:
                update_device_state_db(device_name, action)
                return f"Smart lock is now {action}."
            elif action == "lock" and len(parts) == 3:
                lock_time = parts[2]
                update_device_state_db(device_name, "locked", None, None, lock_time)
                return f"Smart lock will lock at {lock_time}."
            else:
                return "Invalid smart lock command. Use 'smart lock locked/unlocked' or 'smart lock lock <time>'."

        elif device_name == "camera":
            if action in ["on", "off"]:
                update_device_state_db(device_name, action)
                return f"Camera is now {action}."
            else:
                return "Invalid camera command. Use 'camera on/off'."

        elif device_name == "speaker":
            if action in ["on", "off"]:
                update_device_state_db(device_name, action)
                return f"Speaker is now {action}."
            elif action == "play" and len(parts) > 2:
                song = " ".join(parts[2:])
                return f"Playing '{song}' on the speaker."
            else:
                return "Invalid speaker command. Use 'speaker on/off' or 'speaker play <song>'."

        elif action in ["on", "off"]:
            update_device_state_db(device_name, action)
            return f"{device_name} is now {action}."
        else:
            return "Invalid command"
    except Exception as e:
        logging.error(f"Error processing command: {e}")
        return f"Error: {str(e)}"

# Handle client connections
async def handle_client(reader, writer):
    client_address = writer.get_extra_info('peername')
    logging.info(f"New connection from {client_address}")

    try:
        encrypted_auth_message = await reader.read(1024)
        auth_message = decrypt_message(encrypted_auth_message.decode('utf-8'), SECRET_KEY)
        logging.info(f"Authentication attempt: {auth_message}")

        if auth_message.startswith("AUTH"):
            _, username, password = auth_message.split(' ')
            if authenticate_user(username, password):
                response = "Authentication successful"
                logging.info(f"User '{username}' authenticated.")
            else:
                response = "Authentication failed"
                logging.warning(f"User '{username}' failed authentication.")
                encrypted_response = encrypt_message(response, SECRET_KEY)
                writer.write(encrypted_response.encode('utf-8'))
                await writer.drain()
                writer.close()
                return

            encrypted_response = encrypt_message(response, SECRET_KEY)
            writer.write(encrypted_response.encode('utf-8'))
            await writer.drain()

        while True:
            data = await reader.read(1024)
            if not data:
                break

            encrypted_message = data.decode('utf-8')
            command = decrypt_message(encrypted_message, SECRET_KEY)
            response = await process_command(command)
            encrypted_response = encrypt_message(response, SECRET_KEY)

            writer.write(encrypted_response.encode('utf-8'))
            await writer.drain()

    except Exception as e:
        logging.error(f"Error handling client {client_address}: {e}")
    finally:
        writer.close()
        logging.info(f"Connection with {client_address} closed.")

# Main server loop
async def main():
    init_database()
    server = await asyncio.start_server(handle_client, "127.0.0.1", 12345)
    logging.info("Server is running on 127.0.0.1:12345")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
