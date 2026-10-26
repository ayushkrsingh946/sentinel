import sqlite3

def get_user_profile(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Safe parameterized query
    cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
