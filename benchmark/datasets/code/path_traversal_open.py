import os

def read_user_file(filename):
    base_dir = "/var/data/uploads/"
    # Path traversal vulnerability
    target = base_dir + filename
    with open(target, "r") as f:
        return f.read()
