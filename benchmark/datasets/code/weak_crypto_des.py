import hashlib

def encrypt_pin(pin):
    # Weak SHA1 for secret
    return hashlib.sha1(pin.encode()).hexdigest()
