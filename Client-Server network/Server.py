import asyncio
import sqlite3
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import getrandbits
import base64
import logging
import random
import string
import os
from argon2 import PasswordHasher
from passlib.hash import sha256_crypt as PasswordHashe


# Logging setup
logging.basicConfig(
    filename="server.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Hardcoded admin credentials
raw_key = b'my_secret_key_too_long!'
SECRET_KEY = raw_key[:16]

# Shared secret key (must be 16, 24, or 32 bytes long)
HARD_CODED_USERNAME = "admin"
HARD_CODED_PASSWORD = "password123"


# Encryption function
def encrypt_message(message, key, packet_id):
    """
    Encrypt a message using AES-CBC.

    Args:
        message (str): The plaintext message to encrypt.
        key (bytes): The shared secret key for encryption.
        packet_id (str): Unique packet ID for the message.

    Returns:
        str: Base64-encoded encrypted message or None if encryption fails.
    """
    try:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        message_with_id = f"{packet_id}:{message}"
        encrypted = cipher.encrypt(pad(message_with_id.encode("utf-8"), AES.block_size))
        return base64.b64encode(iv + encrypted).decode("utf-8") 
    except Exception as e:
        logging.error(f"[ENCRYPTION ERROR] {e}")
        return None

# Decryption function
def decrypt_message(encrypted_message, key, expected_packet_id):
    """
    Decrypt a message using AES-CBC.

    Args:
        encrypted_message (str): Base64-encoded encrypted message to decrypt.
        key (bytes): The shared secret key for decryption.
        expected_packet_id (str): Packet ID expected in the decrypted message.

    Returns:
        str: Decrypted plaintext message or an error message if decryption fails.
    """
    try:
        raw_data = base64.b64decode(encrypted_message)
        if len(raw_data) < 16:
            raise ValueError("Message too short for valid IV.")
        iv = raw_data[:16]
        encrypted = raw_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted), AES.block_size)
        decrypted_message = decrypted_data.decode("utf-8") 
        packet_id, message = decrypted_message.split(":", 1)

        # Check for replay attacks
        if packet_id != expected_packet_id:
            raise ValueError("Packet ID mismatch. Possible replay attack detected.") 
        return message 
    except base64.binascii.Error as e:
        logging.error(f"[DECRYPTION ERROR] Base64 decoding failed: {e}")
    except ValueError as e:
        logging.error(f"[DECRYPTION ERROR] Decryption failed: {e}")
    except Exception as e: 
        logging.error(f"[DECRYPTION ERROR] {e}")
        return "[ERROR] Unable to decrypt the client's message."
# Diffie-Hellman key exchange functions
def generate_dh_keypair():
    """
    Generate a Diffie-Hellman key pair.

    Returns:
        tuple: A private key and public key.
    """
    private_key = getrandbits(2048)
    public_key = pow(2, private_key, 2**2048 - 1)
    return private_key, public_key

def derive_shared_key(private_key, received_public_key):
    """
    Derive a shared secret key using Diffie-Hellman.

    Args:
        private_key (int): The server's private key.
        received_public_key (int): The client's public key.

    Returns:
        bytes: The derived shared key truncated to 16 bytes.
    """
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

# Initialize the SQLite database for devices
def initialize_database():
    """
    Initialize the SQLite database for storing device states.

    Returns:
        sqlite3.Connection: A connection to the initialized database.
    """
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

# Fetch device state from the database
def get_device_state(conn, device_name):
    """
    Retrieve the state of a device from the database.

    Args:
        conn (sqlite3.Connection): Database connection.
        device_name (str): Name of the device.

    Returns:
        tuple: Device state information or None if the device does not exist.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT device_state, temperature, speed, lock_time FROM devices WHERE LOWER(device_name) = LOWER(?)", (device_name,))
    return cursor.fetchone()

# Update device state in the database
def update_device_state_db(conn, device_name, state=None, temperature=None, speed=None, lock_time=None):
    """
    Update the state of a device in the database.

    Args:
        conn (sqlite3.Connection): Database connection.
        device_name (str): Name of the device.
        state (str, optional): New state of the device.
        temperature (int, optional): New temperature setting.
        speed (str, optional): New speed setting.
        lock_time (str, optional): New lock time setting.
    """
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE devices SET device_state = ?, temperature = ?, speed = ?, lock_time = ? WHERE device_name = ?",
        (state, temperature, speed, lock_time, device_name)
    )
    conn.commit()

def create_error_response(error_message):
    logging.error(f"[ERROR RESPONSE] {error_message}")
    return encrypt_message(f"[ERROR] {error_message}", SECRET_KEY)

# Validate command structure and content
def validate_command(command):
    parts = command.split()
    if len(parts) < 2:
        return "Invalid command format. Must include a device and action (e.g., 'light on')."
    # Reconstruct multi-word device names
    if len(parts) >= 2 and parts[0] == "smart" and parts[1] == "lock":
        device_name = "smart lock"
        action = parts[2] if len(parts) > 2 else None
    else:
        device_name = parts[0]
        action = parts[1] if len(parts) > 1 else None

    valid_devices = ["light", "fan", "thermostat", "smart lock", "camera", "speaker"]
    valid_actions = {
        "light": ["on", "off"],
        "fan": ["on", "off", "low", "medium", "high"],
        "thermostat": ["get", "set"],
        "smart lock": ["locked", "unlocked", "lock"],
        "camera": ["on", "off"],
        "speaker": ["on", "off", "play"]
    }

    if device_name not in valid_devices:
        return f"Unknown device '{device_name}'. Valid devices are: {', '.join(valid_devices)}."

    if action not in valid_actions.get(device_name, []):
        return f"Invalid action '{action}' for device '{device_name}'. Valid actions are: {', '.join(valid_actions[device_name])}."

    if device_name == "thermostat" and action == "set" and len(parts) != 3:
        return "Thermostat 'set' command must include a temperature value (e.g., 'thermostat set 25')."

    if device_name == "smart lock" and action == "lock" and len(parts) < 3:
        return "Smart lock 'lock' command must include a time (e.g., 'smart lock lock 10:00 AM')."

    return None  # No errors

# Process client commands
async def process_command(conn, command, packet_id, shared_key):
    """
    Process commands received from the client.

    Args:
        conn (sqlite3.Connection): Database connection.
        command (str): Command received from the client.
        packet_id (str): Packet ID for the command.
        shared_key (bytes): Shared encryption key.

    Returns:
        str: Encrypted response message.
    """
    try:
        logging.info(f"Processing command: {command}")

        # Validate command structure
        validation_error = validate_command(command)
        if validation_error:
            logging.info(f"Validation error: {validation_error}")
            return encrypt_message(f"[ERROR] {validation_error}", shared_key, packet_id)
        
        parts = command.split()
        device_name, action = parts[0], parts[1]

        # Multi-word devices like "smart lock"
        if len(parts) > 2 and parts[0] == "smart" and parts[1] == "lock":
            device_name = "smart lock"
            action = parts[2] if len(parts) > 2 else None
        
        device_state = get_device_state(conn, device_name)
        if not device_state:
            return encrypt_message(f"[ERROR] Device '{device_name}' not found.", shared_key, packet_id)

            
        # Process device-specific actions
        if device_name == "light":
                if action in ["on", "off"]:
                    update_device_state_db(conn, device_name, state=action)
                    return encrypt_message(f"Light turned {action}.", shared_key, packet_id)

        elif device_name == "thermostat":
            if action == "get":
                _, temperature, _, _ = device_state
                return encrypt_message(f"Current temperature is {temperature}°C.", shared_key, packet_id)
            elif action == "set" and len(parts) == 3:
                try:
                    temperature = int(parts[2])
                    update_device_state_db(conn, device_name, state="on", temperature=temperature)
                    return encrypt_message(f"Thermostat set to {temperature}°C.", shared_key, packet_id)
                except ValueError:
                    return encrypt_message("[ERROR] Invalid temperature value. Please provide an integer.", shared_key, packet_id)



        elif device_name == "fan":
                if action in ["low", "medium", "high"]:
                    update_device_state_db(conn, device_name, state="on", speed=action)
                    return encrypt_message(f"Fan set to {action} speed.", shared_key, packet_id)
                elif action in ["on", "off"]:
                    update_device_state_db(conn, device_name, state=action)
                    return encrypt_message(f"Fan turned {action}.", shared_key, packet_id)

        elif device_name == "smart lock":
            state, _, _, lock_time = device_state

            if action in ["locked", "unlocked"]:
                # Update the database with the new state
                update_device_state_db(conn, device_name, state=action)
                return encrypt_message(f"Smart lock is now {action}.", shared_key, packet_id)

            elif action == "lock" and len(parts) >= 3:
                # Extract lock time from the command
                lock_time = " ".join(parts[2:])
                update_device_state_db(conn, device_name, state="locked", lock_time=lock_time)
                return encrypt_message(f"Smart lock will lock at {lock_time}.", shared_key, packet_id)

        elif device_name == "camera":
            if action in ["on", "off"]:
                update_device_state_db(conn, device_name, state=action)
                return encrypt_message(f"Camera is now {action}.", shared_key, packet_id)

        elif device_name == "speaker":
            if action in ["on", "off"]:
                update_device_state_db(conn, device_name, state=action)
                return encrypt_message(f"Speaker is now {action}.", shared_key, packet_id)
            elif action == "play" and len(parts) > 2:
                    song = " ".join(parts[2:])
                    return encrypt_message(f"Playing '{song}' on the speaker.", shared_key, packet_id)

        # Default case for unhandled commands
        return encrypt_message(f"[ERROR] Unknown action '{action}' for device '{device_name}'.", shared_key, packet_id)


    except Exception as e:
        logging.error(f"[COMMAND ERROR] {e}")
        return encrypt_message("[ERROR] An error occurred while processing the command.", shared_key, packet_id)

async def handle_client(reader, writer):
    conn = sqlite3.connect("smart_home.db")
    try:
        client_address = writer.get_extra_info('peername')
        logging.info(f"New connection from {client_address}")

        # Receive the client's public key
        client_key_bytes = await reader.read(2048)
        client_public_key = int.from_bytes(client_key_bytes, 'big')

        # Generate the Diffie-Hellman keypair
        private_key, public_key = generate_dh_keypair()

        # Send the server's public key to the client
        public_key_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big')
        writer.write(public_key_bytes)
        await writer.drain()

        # Derive the shared key
        shared_key = derive_shared_key(private_key, client_public_key)
        if len(shared_key) not in [16, 24, 32]: 
            shared_key = shared_key[:16] # Ensure the key is 16 bytes
        logging.info(f"[INFO] Shared key established with {client_address}: {shared_key.hex()}")

        encrypted_auth_message = await reader.read(2048)     
        received_data = encrypted_auth_message.decode("utf-8").split(":", 1)
        if len(received_data) != 2:
            logging.error("[SERVER] Invalid packet format during authentication.")
            return
        packet_id, encrypted_message = received_data

        auth_message = decrypt_message(encrypted_message, shared_key, packet_id)
        if not auth_message or not auth_message.startswith("AUTH"):
            response = encrypt_message("Invalid authentication message", shared_key, packet_id)
            writer.write(response.encode("utf-8"))
            await writer.drain()
            return

        _, username, password = auth_message.split()
        if username != HARD_CODED_USERNAME or password != HARD_CODED_PASSWORD:
            response = encrypt_message("Authentication failed: Invalid username or password", shared_key, packet_id)
            writer.write(response.encode("utf-8"))
            await writer.drain()
            return

        # Authentication successful
        response = encrypt_message("Authentication successful", shared_key, packet_id)
        writer.write(response.encode("utf-8"))
        await writer.drain()

        while True:
            try:
                encrypted_command = await reader.read(2048)
                if not encrypted_command:  # Client disconnected
                    logging.info(f"[SERVER] Client {client_address} disconnected.")
                    break
                # Split and decrypt the command
                received_data = encrypted_command.decode("utf-8").split(":", 1)
                if len(received_data) != 2:
                    logging.error("[SERVER] Invalid packet format.")
                    break

                packet_id, encrypted_message = received_data
                logging.info(f"[SERVER] Received packet ID: {packet_id}")
                command = decrypt_message(encrypted_message, shared_key, packet_id)

                if command == "[ERROR] Unable to decrypt the server's response":
                    response = encrypt_message("[ERROR] Decryption failed or invalid message format.", shared_key, packet_id)
                else:
                    logging.info(f"[SERVER] Processing command: {command}")
                response = await process_command(conn, command, packet_id, shared_key)

                # Send the response back to the client
                writer.write(response.encode("utf-8"))
                await writer.drain()
            except Exception as e:
                logging.error(f"[SERVER ERROR] {e}")
                
            except asyncio.TimeoutError:
                response = encrypt_message("Session timed out due to inactivity.", shared_key, packet_id)
                writer.write(response.encode("utf-8"))
                await writer.drain()
                break

            except ConnectionResetError:
                logging.warning(f"[SERVER] Client {client_address} disconnected abruptly.")
                break

    except Exception as e:
        logging.error(f"[SERVER ERROR] Unexpected error: {e}")
        fallback_packet_id = "00000000-0000-0000-0000-000000000000"  # Fallback packet ID
        response = encrypt_message("Server encountered an unexpected error.", shared_key, fallback_packet_id)
        writer.write(response.encode("utf-8"))
        writer.close()
        await writer.wait_closed()
        conn.close()
        logging.info(f"[SERVER] Connection with {client_address} closed.")



async def main():
    conn = initialize_database()
    conn.close()
    server = await asyncio.start_server(handle_client, "127.0.0.1", 12345)
    logging.info("Server is running on 127.0.0.1:12345")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
