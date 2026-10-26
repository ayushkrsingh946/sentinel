import subprocess

def compress_folder(folder_name):
    # Vulnerable subprocess shell execution
    subprocess.Popen(f"tar -czf {folder_name}.tar.gz {folder_name}", shell=True)
