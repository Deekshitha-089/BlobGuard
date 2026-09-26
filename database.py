
import sqlite3


# Name of our database
DATABASE = "blobguard.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)

    # Allows us to access columns using their names
    connection.row_factory = sqlite3.Row

    return connection


def create_tables():

    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()

    print("Users table created successfully!")


if __name__ == "__main__":
    create_tables()