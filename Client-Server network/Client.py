import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import getrandbits
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
        return "[ERROR] Unable to decrypt the server's response."

# Diffie-Hellman key exchange functions
def generate_dh_keypair():
    private_key = getrandbits(2048)
    public_key = pow(2, private_key, 2**2048 - 1)
    return private_key, public_key

def derive_shared_key(private_key, received_public_key):
    shared_key = pow(received_public_key, private_key, 2**2048 - 1)
    byte_length = (shared_key.bit_length() + 7) // 8
    return shared_key.to_bytes(byte_length, 'big')[:16]

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

                # Key negotiation phase
        # Generate the Diffie-Hellman keypair
        private_key, public_key = generate_dh_keypair()

        # Send the public key to the server
        public_key_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big')
        writer.write(public_key_bytes)
        await writer.drain()

        # Receive the server's public key
        server_key_bytes = await reader.read(2048)
        server_public_key = int.from_bytes(server_key_bytes, 'big')

        # Derive the shared key
        shared_key = derive_shared_key(private_key, server_public_key)
        if len(shared_key) not in [16, 24, 32]: shared_key = shared_key[:16] # Ensure the key is 16 bytes
        print(f"[INFO] Shared key established: {shared_key.hex()}")

        # Use the shared key for encryption/decryption
        global SECRET_KEY
        SECRET_KEY = shared_key

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
        encrypted_response = await reader.read(2048)
        response = decrypt_message(encrypted_response.decode("utf-8"), SECRET_KEY)
        print(f"[SERVER RESPONSE] {response}")

        # If authenticated successfully, interact with the server
        if "Authentication successful" in response: 
            while True:
                command = input("Hi, please enter a command ('help' for commands, 'exit' to quit): ").strip()

                if command.lower() == "exit":
                    print("Closing connection...")
                    writer.close()
                    await writer.wait_closed()
                    print("[DISCONNECTED] Client connection closed.")
                    break

                if command.lower() == "help":
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
                    continue  # Restart the loop after showing help

                # Encrypt and send the command to the server
                encrypted_message = encrypt_message(command, SECRET_KEY)
                if not encrypted_message:
                    print("[CLIENT ERROR] Failed to encrypt command message.")
                    continue  # Restart loop if encryption fails

                writer.write(encrypted_message.encode("utf-8"))
                await writer.drain()

                # Receive and decrypt the server's response
                try:
                    encrypted_response = await asyncio.wait_for(reader.read(2048), timeout=30.0)
                    if not encrypted_response:  # Server disconnected
                        print("[SERVER] Disconnected unexpectedly.")
                        break

                    response = decrypt_message(encrypted_response.decode("utf-8"), SECRET_KEY)
                    print(f"[DEBUG] Raw response: {encrypted_response}")  # Debug log
                    print(f"[DEBUG] Decrypted response: {response}")  # Debug log

                    if "[ERROR]" in response or "set" in response or "temperature" in response:
                        print(f"[SERVER RESPONSE] {response}")
                    else:
                        print(f"\033[91m[SERVER RESPONSE] {response}\033[0m")  # Red color for errors
                except (asyncio.TimeoutError, ConnectionResetError):
                    print("[CLIENT ERROR] Server not responding. Closing connection.")
                    break


    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass
        print("[DISCONNECTED] Client connection closed.")

        

if __name__ == "__main__":
    asyncio.run(start_client())
