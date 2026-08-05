import sqlite3


def save_file(filename, filepath):

    connection = sqlite3.connect("database/scanner.db")
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO scans(filename, filepath) VALUES (?, ?)",
        (filename, filepath)
    )

    connection.commit()
    connection.close()


def get_all_scans():

    connection = sqlite3.connect("database/scanner.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, filename, filepath, upload_time
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    return scans