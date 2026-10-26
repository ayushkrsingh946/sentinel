import subprocess

def list_files(directory):
    # Safe subprocess execution with array args and shell=False
    return subprocess.run(["ls", "-la", directory], shell=False, check=True, capture_output=True)
