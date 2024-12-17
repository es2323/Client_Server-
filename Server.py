import asyncio
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from argon2 import PasswordHasher
import logging
import random
import string
import os 

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

# Helper Functions
def generate_random_username():
    """Generate a random username."""
    return f"user{random.randint(1000, 9999)}"

def generate_random_password(existing_password="testpassword", length=12):
    """Generate a strong random password with a specified length."""
    if not isinstance(length, int):  
        logging.info(f"Invalid length provided: {length}. Using default length of 12.")
        length = 12  # Fallback to 12 if an incorrect value is provided

    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    random_password = ''.join(random.choice(chars) for _ in range(length))

    combined_password = existing_password + random_password
    return ''.join(random.sample(combined_password, len(combined_password)))

def hash_password(password):
    """Hash the password using Argon2."""
    ph = PasswordHasher()
    return ph.hash(password)

def verify_password(stored_password, provided_password):
    """Verify the password."""
    ph = PasswordHasher()
    try:
        return ph.verify(stored_password, provided_password)
    except Exception:
        return False

# Alter the schema if needed (add missing columns)
def alter_devices_table(conn):
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(devices)")
    columns = [row[1] for row in cursor.fetchall()]  # Extract column names
    if "speed" not in columns:
        cursor.execute("ALTER TABLE devices ADD COLUMN speed TEXT")
    if "lock_time" not in columns:
        cursor.execute("ALTER TABLE devices ADD COLUMN lock_time TEXT")
    conn.commit()


# Initialize SQLite Database
def init_database(conn):
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
            device_name TEXT PRIMARY KEY,
            device_state TEXT,
            temperature INTEGER,
            speed TEXT,
            lock_time TEXT
        )
    """)

    # Alter schema to match new requirements
    alter_devices_table(conn)
    logging.info("Tables 'users' and 'devices' created or verified.")

    # Generate a random password based on an existing one
    existing_password = "testpassword"
    generated_password = generate_random_password(existing_password)
    logging.info(f"Generated password: {generated_password}")
    print(f"Generated Password: {generated_password}")

    hashed_password = hash_password(generated_password)
    logging.info(f"Hashed password stored: {hashed_password}")


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

    # Insert default user with hashed password
# Insert or Update the default user
    cursor.execute("""
        INSERT INTO users (username, password)
        VALUES (?, ?)
        ON CONFLICT(username) DO UPDATE SET password = excluded.password
    """, ("testuser", hashed_password))

    conn.commit()
    conn.close()
    logging.info("Default devices and users inserted.")

# Assign Temporary Credentials
def assign_temporary_credentials():
    username = generate_random_username()
    password = generate_random_password()
    hashed_password = hash_password(password)

    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

    return username, password

# Authenticate a user
def authenticate_user(username, password):
    with sqlite3.connect("smart_home.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return verify_password(result[0], password)
        return False

def update_password(username, new_password):
    hashed_password = hash_password(new_password)
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
    conn.commit()
    conn.close()


# Fetch device state
def get_device_state(conn, device_name):
    cursor = conn.cursor()
    cursor.execute("SELECT state, temperature, speed, lock_time FROM devices WHERE LOWER(name) = LOWER(?)", (device_name,))
    return cursor.fetchone()

# Update device state
def update_device_state_db(conn,  device_name, state=None, temperature=None, speed=None, lock_time=None):
    cursor = conn.cursor()
    cursor.execute(
            "UPDATE devices SET state = ?, temperature = ?, speed = ?, lock_time = ? WHERE name = ?",
            (state, temperature, speed, lock_time, device_name)
        )
    conn.commit()

# Decrypt message
def decrypt_message(encrypted_message, key):
    try:
        raw_data = base64.b64decode(encrypted_message)
        
        # Ensure message contains at least 16 bytes (IV length)
        if len(raw_data) < 16:
            raise ValueError("Received message is too short to contain a valid IV.")

        iv = raw_data[:16]  # Extract IV
        encrypted = raw_data[16:]  # Extract encrypted message content

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted), AES.block_size)

        return decrypted_data.decode('utf-8')  # Convert decrypted data back to string
    except (ValueError, UnicodeDecodeError, base64.binascii.Error) as e:
        logging.error(f"Server decryption error: {e}")
        return "Invalid message received or decryption error"


# Encrypt message
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted).decode('utf-8')

# Process client commands
async def process_command(conn, command):
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
            elif action == "lock" and len(parts) >= 3:
                lock_time = " ".join(parts[2:])
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

async def handle_client(reader, writer):
    client_address = writer.get_extra_info('peername')
    logging.info(f"New connection from {client_address}")

    try:
        encrypted_auth_message = await reader.read(1024)
        logging.info(f"Received raw encrypted authentication message: {encrypted_auth_message}")

        auth_message = decrypt_message(encrypted_auth_message.decode('utf-8'), SECRET_KEY)
        logging.info(f"Decrypted authentication message: {auth_message}")

        if auth_message.startswith("AUTH"):
            _, username, password = auth_message.split(' ')
            if authenticate_user(username, password):
                response = "Authentication successful"
                logging.info(f"User '{username}' authenticated successfully.")
            else:
                response = "Authentication failed"

            encrypted_response = encrypt_message(response, SECRET_KEY)
            writer.write(encrypted_response.encode('utf-8'))
            await writer.drain()

        while True:
            data = await reader.read(1024)
            if not data:
                break

            encrypted_message = data.decode('utf-8')
            logging.info(f"Received encrypted client command: {encrypted_message}")

            command = decrypt_message(encrypted_message, SECRET_KEY)
            logging.info(f"Decrypted client command: {command}")

            response = await process_command(command)
            encrypted_response = encrypt_message(response, SECRET_KEY)

            writer.write(encrypted_response.encode('utf-8'))
            await writer.drain()

    except Exception as e:
        logging.error(f"Client handling error: {e}")
    finally:
        writer.close()
        logging.info(f"Connection with {client_address} closed.")


# Main server loop
async def main():
    conn = sqlite3.connect("smart_home.db")
    init_database(conn)
    username, temp_password = assign_temporary_credentials()
    logging.info(f"Assigned credentials: Username: {username}, Password: {temp_password}")
    print(f"Temporary Credentials - Username: {username}, Password: {temp_password}")

    server = await asyncio.start_server(handle_client, "127.0.0.1", 12345)
    logging.info("Server running on 127.0.0.1:12345")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())