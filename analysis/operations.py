import os
import sqlite3
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

def get_effective_db_path():
    if os.environ.get("VERCEL") == "1":
        return "/tmp/scanner.db"
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(base_dir)
    target_dir = os.path.join(project_root, "database")
    if not os.access(project_root, os.W_OK) or (os.path.exists(target_dir) and not os.access(target_dir, os.W_OK)):
        return "/tmp/scanner.db"
    return os.path.join(target_dir, "scanner.db")

DB_PATH = get_effective_db_path()


@contextmanager
def get_db_connection(db_path=None):
    """Context manager for safely managing SQLite database connections."""
    if not db_path:
        db_path = get_effective_db_path()

    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except Exception:
            db_path = "/tmp/scanner.db"
            os.makedirs("/tmp", exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        if not db_path.startswith("/tmp"):
            try:
                connection.execute("PRAGMA journal_mode=WAL")
            except Exception:
                pass
        connection.execute("PRAGMA foreign_keys=ON")
        yield connection
        connection.commit()
    except Exception as e:
        connection.rollback()
        logger.error("Database operation failed: %s", e)
        raise
    finally:
        connection.close()


def save_file(
    filename,
    filepath,
    md5=None,
    sha1=None,
    sha256=None,
    entropy=None,
    entropy_verdict=None,
    signature_status=None,
    publisher=None,
    is_trusted=None,
    risk_score=None,
    threat_level=None,
    db_path=DB_PATH,
):
    """Save upload scan record to database with optional detailed security metrics."""
    try:
        with get_db_connection(db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO scans(
                    filename, filepath, md5, sha1, sha256,
                    entropy, entropy_verdict, signature_status,
                    publisher, is_trusted, risk_score, threat_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    filename,
                    filepath,
                    md5,
                    sha1,
                    sha256,
                    entropy,
                    entropy_verdict,
                    signature_status,
                    publisher,
                    1 if is_trusted else 0 if is_trusted is not None else None,
                    risk_score,
                    threat_level,
                ),
            )
            return cursor.lastrowid
    except sqlite3.Error as e:
        logger.error("Error saving file scan record for %s: %s", filename, e)
        return None


def get_all_scans(limit=100, db_path=DB_PATH):
    """Retrieve scan records from database as tuples, ordered by ID DESC."""
    try:
        with get_db_connection(db_path) as connection:
            cursor = connection.cursor()
            if limit:
                cursor.execute(
                    """
                    SELECT id, filename, filepath, upload_time
                    FROM scans
                    ORDER BY id DESC
                    LIMIT ?
                """,
                    (limit,),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, filename, filepath, upload_time
                    FROM scans
                    ORDER BY id DESC
                """
                )
            scans = cursor.fetchall()
            # Return list of tuples for backwards compatibility
            return [tuple(row) for row in scans]
    except sqlite3.Error as e:
        logger.error("Error fetching scan records: %s", e)
        return []


def get_all_scans_dict(limit=100, db_path=DB_PATH):
    """Retrieve complete scan records from database as dictionary list."""
    try:
        with get_db_connection(db_path) as connection:
            cursor = connection.cursor()
            query = """
                SELECT id, filename, filepath, upload_time, md5, sha1, sha256,
                       entropy, entropy_verdict, signature_status, publisher,
                       is_trusted, risk_score, threat_level
                FROM scans
                ORDER BY id DESC
            """
            if limit:
                cursor.execute(query + " LIMIT ?", (limit,))
            else:
                cursor.execute(query)

            scans = cursor.fetchall()
            return [dict(row) for row in scans]
    except sqlite3.Error as e:
        logger.error("Error fetching scan records dict: %s", e)
        return []


def get_scan_by_id(scan_id, db_path=DB_PATH):
    """Retrieve a single scan record by ID as a dictionary."""
    try:
        with get_db_connection(db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT id, filename, filepath, upload_time, md5, sha1, sha256,
                       entropy, entropy_verdict, signature_status, publisher,
                       is_trusted, risk_score, threat_level
                FROM scans
                WHERE id = ?
                """,
                (scan_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error("Error fetching scan record #%s: %s", scan_id, e)
        return None


def delete_all_scans(db_path=DB_PATH):
    """Delete all scan records from the SQLite database."""
    try:
        with get_db_connection(db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM scans;")
            connection.commit()
            logger.info("All scan history records deleted successfully.")
            return True
    except sqlite3.Error as e:
        logger.error("Error deleting all scan records: %s", e)
        return False


def delete_scan_by_id(scan_id, db_path=DB_PATH):
    """Delete a single scan record by ID."""
    try:
        with get_db_connection(db_path) as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))
            connection.commit()
            logger.info("Scan record #%s deleted successfully.", scan_id)
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error("Error deleting scan record #%s: %s", scan_id, e)
        return False