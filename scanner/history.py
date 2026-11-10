"""SQLite persistence for VulnCloud assessment history."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


@contextmanager
def _connect(db_path):
    """Open a SQLite connection and always close it after the operation."""
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_history(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                target TEXT NOT NULL,
                success INTEGER NOT NULL,
                status_code INTEGER,
                score INTEGER,
                rating TEXT,
                result_json TEXT NOT NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessments_scanned_at "
            "ON assessments(scanned_at DESC)"
        )


def save_assessment(db_path, result):
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    score_data = result.get("score") or {}
    with _connect(db_path) as connection:
        cursor = connection.execute(
            """INSERT INTO assessments
               (scanned_at, target, success, status_code, score, rating, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scanned_at,
                result.get("target") or "",
                1 if result.get("success") else 0,
                result.get("status_code"),
                score_data.get("score"),
                score_data.get("rating"),
                json.dumps(result, ensure_ascii=False),
            ),
        )
        return cursor.lastrowid


def list_assessments(db_path, limit=100):
    with _connect(db_path) as connection:
        rows = connection.execute(
            """SELECT id, scanned_at, target, success, status_code, score, rating
               FROM assessments ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_assessment(db_path, assessment_id):
    with _connect(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["result"] = json.loads(item.pop("result_json"))
    return item
