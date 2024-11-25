import asyncio
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Shared secret key (must be 16, 24, or 32 bytes long)
raw_key = b'my_secret_key_too_long!'
SECRET_KEY = raw_key[:16]

# Initialize SQLite Database
def init_database():
    conn = sqlite3.connect("smart_home.db")  # Creates `smart_home.db` file
    cursor = conn.cursor()
    print("Initializing database...")
    # Create devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            name TEXT PRIMARY KEY,
            state TEXT,
            temperature INTEGER
        )
    """)

    print("Table 'devices' created or verified.")
    # Insert default devices
    default_devices = [
        ("light", "off", None),
        ("thermostat", "off", 20),
        ("fan", "off", None),
        ("smart lock", "locked", None),
    ]
    cursor.executemany("INSERT OR IGNORE INTO devices VALUES (?, ?, ?)", default_devices)
    conn.commit()
    conn.close()
    print("Default devices inserted.")

# Fetch device state
def get_device_state(device_name):
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute("SELECT state, temperature FROM devices WHERE name = ?", (device_name,))
    result = cursor.fetchone()
    conn.close()
    return result

# Update device state
def update_device_state_db(device_name, state, temperature=None):
    conn = sqlite3.connect("smart_home.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE devices SET state = ?, temperature = ? WHERE name = ?",
        (state, temperature, device_name),
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
        print(f"Received raw command: {command}")  # Debugging input

        command = command.lower()
        print(f"Processed to lowercase: {command}")  # Debugging input
        parts = command.split(' ')
        device_name = ' '.join(parts[:2]) if len(parts) > 2 else parts[0]
        action = parts[1] if len(parts) > 1 else None
        print(f"Device: {device_name}, Action: {action}")

        device_state = get_device_state(device_name)
        if device_state is None:
            print("Device not found in database.")
            return "Device not found"

        if action == "on" or action == "off":
            update_device_state_db(device_name, action)
            return f"{device_name} is now {action}"
        elif device_name == "thermostat" and action == "set" and len(parts) == 3:
            temperature = int(parts[2])
            update_device_state_db(device_name, "on", temperature)
            return f"Thermostat set to {temperature}°C"
        elif device_name == "smart lock" and action in ["locked", "unlocked"]:
            update_device_state_db(device_name, action)
            return f"Smart lock is now {action}"
        else:
            print("Invalid command received.")
            return "Invalid command"
    except Exception as e:
        print(f"Error while processing command: {e}")  # Debug exception
        return f"Error: {str(e)}"

# Handle client connections
async def handle_client(reader, writer):
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

async def main():
    init_database()  # Initialize the database
    server = await asyncio.start_server(handle_client, "127.0.0.1", 12345)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
