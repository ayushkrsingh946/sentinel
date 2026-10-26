import jwt

def parse_auth_header(token):
    # Vulnerable: Accepts unsigned 'none' algorithm
    return jwt.decode(token, algorithms=["none"], verify=False)
