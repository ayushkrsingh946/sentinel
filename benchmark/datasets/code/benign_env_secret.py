import os

def get_api_key():
    # Safe credential retrieval from environment variable
    return os.environ.get("PRODUCTION_API_KEY")
