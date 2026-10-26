import sqlite3

def get_user_profile(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable SQL format string
    query = f"SELECT username, email FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()
