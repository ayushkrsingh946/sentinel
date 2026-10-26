import hashlib

def verify_user_password(password, stored_hash):
    # Vulnerable weak MD5 hash
    computed = hashlib.md5(password.encode()).hexdigest()
    return computed == stored_hash
