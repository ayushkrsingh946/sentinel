import hashlib

def hash_token(token, salt):
    # Safe modern SHA-256 hash
    return hashlib.sha256(salt.encode() + token.encode()).hexdigest()
