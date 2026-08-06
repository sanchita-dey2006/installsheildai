import os
import sqlite3
import logging

logger = logging.getLogger(__name__)

DB_DIR = "database"
DB_PATH = os.path.join(DB_DIR, "scanner.db")


def create_database(db_path=DB_PATH):
    """Initialize database schema, column migrations, indexes, and SQLite performance PRAGMAs."""
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    try:
        with sqlite3.connect(db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA synchronous=NORMAL")

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # Auto-migration: ensure new analysis metric columns exist
            cursor.execute("PRAGMA table_info(scans)")
            existing_columns = {row[1] for row in cursor.fetchall()}

            new_columns = {
                "md5": "TEXT",
                "sha1": "TEXT",
                "sha256": "TEXT",
                "entropy": "REAL",
                "entropy_verdict": "TEXT",
                "signature_status": "TEXT",
                "publisher": "TEXT",
                "is_trusted": "INTEGER",
                "risk_score": "INTEGER",
                "threat_level": "TEXT",
            }

            for col_name, col_type in new_columns.items():
                if col_name not in existing_columns:
                    cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")
                    logger.info("Migrated table 'scans': added column '%s'", col_name)

            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_upload_time 
            ON scans(upload_time DESC)
            """)

            connection.commit()
            logger.info("Database initialized successfully at %s", db_path)
    except sqlite3.Error as e:
        logger.error("Failed to initialize database at %s: %s", db_path, e)
        raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_database()
    print("Database Created Successfully")