# Secure Smart Home Client-Server System
The Secure Smart Home Client-Server System is a Python-based project that facilitates encrypted communication between a client and server to manage smart home devices. It ensures secure and reliable operation using Diffie-Hellman key exchange, AES-CBC encryption, and robust error handling.

# Features
Secure Communication:
Dynamic key exchange using Diffie-Hellman.
End-to-end AES-CBC encryption for all messages.
Authentication:

Username-password-based authentication for access control.
Prevention of replay attacks through unique packet IDs.
Device Management:

Supports multiple devices such as lights, thermostats, fans, cameras, and smart locks.
Real-time updates and retrieval of device states.
list devices command to view the current state of all devices.
Timeout Handling:

Connection timeout after 30 seconds of inactivity.
Graceful disconnection handling for both client and server.
Robust Error Handling:

Comprehensive error messages for invalid commands or system errors.
Server-side logging for debugging and auditing.

# System Requirements
Python: Version 3.8 or higher.
Libraries:
asyncio
sqlite3
pycryptodome
argon2-cffi
passlib

# Usage
Start the Server:
Launch the server script to initialize the database and start listening for client connections.
Connect the Client:
Run the client script to establish a secure connection with the server.
Authentication:
Enter the username and password when prompted.
(Default credentials: testuser/Scorpio123&^!)

# Commands
list devices: View all devices and their current states.
light on/off: Control the light.
fan low/medium/high: Set fan speed.
thermostat get/set <temp>: Get or set the thermostat temperature.
smart lock locked/unlocked: Lock or unlock the smart lock.
exit: Disconnect the client.
