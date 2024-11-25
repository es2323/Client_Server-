import asyncio
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Shared secret key (must be 16, 24, or 32 bytes long)
raw_key = b'my_secret_key_too_long!'  # Example of a 19-byte key
SECRET_KEY = raw_key[:16]  # Truncate to 16 bytes
print(len(SECRET_KEY))  # Should print 16

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)  # Use CBC mode
    iv = cipher.iv  # Initialization vector
    encrypted = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted).decode('utf-8')  # Encode IV + ciphertext

def decrypt_message(encrypted_message, key):
    raw_data = base64.b64decode(encrypted_message)  # Decode the base64-encoded message
    iv = raw_data[:16]  # Extract the first 16 bytes (IV)
    encrypted = raw_data[16:]  # The rest is the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode('utf-8')  # Decrypt and unpad

async def start_client():
    HOST = '127.0.0.1'
    PORT = 12345
    reader, writer = await asyncio.open_connection(HOST, PORT)
    print(f"[CONNECTED] Connected to the server at {HOST}:{PORT}")

    # User-friendly prompt
    while True:
        # Provide an informative and user-friendly prompt
        message = input("Hi, please enter a command to control devices in your Smart Home (e.g., 'light on', 'thermostat set 22', 'fan off', 'smart lock locked')\nType in 'help' to view the list of commands.exit\nType in 'exit' to quit. ")
        
        if message.lower() == 'help':
            print("Here are the available commands:")
            print(" - light on/off")
            print(" - thermostat set <temperature>")
            print(" - fan on/off")
            print(" - smart lock locked/unlocked")
            print("Type 'exit' to quit.")
            continue  # Skip the encryption part and wait for the next command

        if message.lower() == 'exit':
            print("Exiting the Smart Home network.")
            break
        
        # Encrypt the message
        encrypted_message = encrypt_message(message, SECRET_KEY)
        writer.write(encrypted_message.encode('utf-8'))
        await writer.drain()  # Ensure the message is sent

        # Receive the server's encrypted response
        encrypted_response = await reader.read(1024)
        
        # Decrypt the server's response
        response = decrypt_message(encrypted_response.decode('utf-8'), SECRET_KEY)  # Add this line
        print(f"[SERVER RESPONSE] {response}")  # Show the decrypted response

    writer.close()

if __name__ == "__main__":
    asyncio.run(start_client())
