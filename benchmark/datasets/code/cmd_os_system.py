import os

def ping_host(target_ip):
    # Vulnerable OS command injection
    os.system(f"ping -c 1 {target_ip}")
