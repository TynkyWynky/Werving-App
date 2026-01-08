from __future__ import annotations

import os
import sqlite3


def get_database_connection() -> sqlite3.Connection:
    """
    Central DB connection helper.
    DB file defaults to: <werving_app>/database.db
    Override optional via env: SQLITE_DB_PATH
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../werving_app
    default_db = os.path.join(base_dir, "database.db")
    db_path = os.environ.get("SQLITE_DB_PATH", default_db)

    timeout = int(os.environ.get("SQLITE_TIMEOUT_SECONDS", "15"))
    connection = sqlite3.connect(db_path, timeout=timeout)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    return connection
