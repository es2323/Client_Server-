# Adjust a key to exactly 16 bytes
raw_key = b'my_secret_key_too_long!'  # Example of a 19-byte key
SECRET_KEY = raw_key[:16]  # Truncate to 16 bytes
print(len(SECRET_KEY))  # Should print 16
