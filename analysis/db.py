import sqlite3


def create_database():

    connection = sqlite3.connect("database/scanner.db")

    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        filename TEXT,

        filepath TEXT,

        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    )
    """)

    connection.commit()

    connection.close()


if __name__ == "__main__":
    create_database()
    print("Database Created Successfully")