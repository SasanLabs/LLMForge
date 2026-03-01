import os
import sqlite3
from typing import List, Dict, Any


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_DIR = os.path.join(ROOT, "data")
DB_PATH = os.path.join(DB_DIR, "vulndb.sqlite")


def init_db(db_path: str = DB_PATH) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            secret TEXT
        );
        """
    )

    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    if count == 0:
        users = [
            ("alice", "alicepass", "alice_secret_token"),
            ("bob", "bobpass", "bob_secret_token"),
            ("charlie", "charliepass", "charlie_secret_token"),
        ]
        for username, password, secret in users:
            cur.execute(
                "INSERT OR IGNORE INTO users (username, password, secret) VALUES (?, ?, ?)",
                (username, password, secret),
            )
        conn.commit()
    conn.close()


def get_conn(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _assert_safe_clause(clause: str) -> None:
    # Minimal safety: disallow statement separators and destructive keywords
    lower = clause.lower()
    if ";" in clause:
        raise ValueError("semicolon not allowed in clause")
    forbidden = ["drop", "delete", "insert", "update", "create", "alter"]
    for tok in forbidden:
        if tok in lower:
            raise ValueError(f"forbidden token in clause: {tok}")


def execute_raw_select(conn: sqlite3.Connection, clause: str) -> List[Dict[str, Any]]:
    _assert_safe_clause(clause)
    sql = f"SELECT id, username, secret FROM users WHERE {clause}"
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    return [dict(r) for r in rows]


def parameterized_search(conn: sqlite3.Connection, column: str, value: str) -> List[Dict[str, Any]]:
    if column not in ("username", "id"):
        raise ValueError("unsupported column")
    sql = f"SELECT id, username, secret FROM users WHERE {column} = ?"
    cur = conn.cursor()
    cur.execute(sql, (value,))
    rows = cur.fetchall()
    return [dict(r) for r in rows]


def escape_quotes(s: str) -> str:
    return s.replace("'", "''")
