import json

def load_payload(raw_json):
    # Safe standard JSON parsing
    return json.loads(raw_json)
