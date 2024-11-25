import asyncio
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

from Client import encrypt_message

# Shared secret key (must be 16, 24, or 32 bytes long)
raw_key = b'my_secret_key_too_long!'  # Example of a 19-byte key
SECRET_KEY = raw_key[:16]  # Truncate to 16 bytes
print(len(SECRET_KEY))  # Should print 16

# Simulate IoT devices with states
devices = {
    "light": {"state": "off"},
    "thermostat": {"state": "off", "temperature": 20},  # Default temperature is 20°C
    "fan": {"state": "off"},
    "smart lock": {"state": "locked"}  # Change the key to "smart lock"
}

def decrypt_message(encrypted_message, key):
    raw_data = base64.b64decode(encrypted_message)
    iv = raw_data[:16]  # First 16 bytes are the IV
    encrypted = raw_data[16:]  # Rest is the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode('utf-8')

async def update_device_state(command):
    """Update the device state based on the command"""
    global devices
    try:
        parts = command.split(' ')  # Split the command into parts
        device = parts[0]  # The device name is the first part
        action = parts[1]  # The action is the second part

        if device in devices:
            if device == 'thermostat' and len(parts) > 2 and action == 'set':  # Check for "thermostat set <temperature>"
                temperature = int(parts[2])  # Get the temperature value from the command
                devices[device]['state'] = 'on'  # Turn the thermostat on
                devices[device]['temperature'] = temperature  # Set the temperature
                return f"Thermostat set to {temperature}°C"
            elif action == 'on':
                devices[device]['state'] = 'on'  # Turn the device on
                return f"{device} is now on"
            elif action == 'off':
                devices[device]['state'] = 'off'  # Turn the device off
                return f"{device} is now off"
            elif device == 'smart lock' and action in ['locked', 'unlocked']:  # Check for lock/unlock command
                devices[device]['state'] = action
                return f"Smart lock is now {action}"
            else:
                return "Invalid action or device state"
        else:
            return "Device not found"
    except Exception as e:
        return f"Error: {str(e)}"

async def handle_client(reader, writer):
    client_address = writer.get_extra_info('peername')
    print(f"[NEW CONNECTION] {client_address} connected.")
    try:
        while True:
            # Receive the encrypted message
            data = await reader.read(1024)
            if not data:
                break

            encrypted_message = data.decode('utf-8')

            # Decrypt the message
            message = decrypt_message(encrypted_message, SECRET_KEY)
            print(f"[{client_address}] {message}")
            
            # Process the command to control the devices
            response = await update_device_state(message)
            
            # Encrypt and send the response back
            encrypted_response = encrypt_message(response, SECRET_KEY)
            writer.write(encrypted_response.encode('utf-8'))
            await writer.drain()  # Ensure the message is sent
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        print(f"[CLOSING CONNECTION] {client_address}")
        writer.close()

async def start_server():
    HOST = '127.0.0.1'
    PORT = 12345
    server = await asyncio.start_server(handle_client, HOST, PORT)
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(start_server())
