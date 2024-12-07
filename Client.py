import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Shared secret key (must be 16, 24, or 32 bytes long)
raw_key = b'my_secret_key_too_long!'
SECRET_KEY = raw_key[:16]

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt_message(encrypted_message, key):
    raw_data = base64.b64decode(encrypted_message)
    iv = raw_data[:16]
    encrypted = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode('utf-8')

async def start_client():
    HOST = '127.0.0.1'
    PORT = 12345
    reader, writer = await asyncio.open_connection(HOST, PORT)
    print(f"[CONNECTED] Connected to the server at {HOST}:{PORT}")

    # Prompt for username and password
    username = input("Enter your username: ")
    password = input("Enter your password: ")


    # Log the provided credentials for debugging
    print(f"[DEBUG] Username: {username}")
    print(f"[DEBUG] Password: {password}")
    
    auth_message = f"AUTH {username} {password}"
    encrypted_auth_message = encrypt_message(auth_message, SECRET_KEY)
    writer.write(encrypted_auth_message.encode('utf-8'))
    await writer.drain()

    encrypted_response = await reader.read(1024)
    response = decrypt_message(encrypted_response.decode('utf-8'), SECRET_KEY)
    print(f"[SERVER RESPONSE] {response}")

    if response != "Authentication successful":
        print("Authentication failed. Disconnecting.")
        writer.close()
        return

    while True:
        message = input("Hi, please enter a command ('help' for commands, 'exit' to quit): ")

        if message.lower() == 'exit':
            print("Exiting...")
            break  # Exit the while loop and close the client connection

        if message.lower() == 'help':
            print("Available commands:\n"
                "light on/off\n"
                "fan on/off\n"
                "fan low/medium/high\n"
                "thermostat get\n"
                "thermostat set <temp>\n"
                "smart lock locked/unlocked\n"
                "smart lock lock <time in 12-hour format>\n"
                "camera on/off\n"
                "speaker on/off\n"
                "speaker play <song>")

            continue

        encrypted_message = encrypt_message(message, SECRET_KEY)
        writer.write(encrypted_message.encode('utf-8'))
        await writer.drain()

        encrypted_response = await reader.read(1024)
        response = decrypt_message(encrypted_response.decode('utf-8'), SECRET_KEY)
        print(f"[SERVER RESPONSE] {response}")

    writer.close()


if __name__ == "__main__":
    asyncio.run(start_client())
