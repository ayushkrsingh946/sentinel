import pickle

def load_session(serialized_data):
    # Arbitrary code execution via pickle
    session = pickle.loads(serialized_data)
    return session
