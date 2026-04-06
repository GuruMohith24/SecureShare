import sqlite3
import datetime
from contextlib import contextmanager

DB_PATH = "backend/secure_share.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA secure_delete = ON;")
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_type TEXT DEFAULT 'application/pdf',
            original_size INTEGER DEFAULT 0,
            expires_at TIMESTAMP NOT NULL,
            key_salt BLOB,
            nonce BLOB,
            password_hash TEXT,
            burn_after_read BOOLEAN DEFAULT 0,
            expired BOOLEAN DEFAULT 0,
            uploaded_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT,
            user_email TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA secure_delete = ON;")
    try:
        yield conn
    finally:
        conn.close()


def store_metadata(
    file_id: str,
    filename: str,
    expires_at: datetime.datetime,
    key_salt: bytes,
    nonce: bytes,
    burn_after_read: bool = False,
    password_hash: str = None,
    original_size: int = 0,
    uploaded_by: str = None,
    file_type: str = "application/pdf",
):
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO files (id, filename, file_type, original_size, expires_at,
                               key_salt, nonce, burn_after_read, password_hash,
                               expired, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                file_id,
                filename,
                file_type,
                original_size,
                expires_at.isoformat() if hasattr(expires_at, "isoformat") else expires_at,
                key_salt,
                nonce,
                1 if burn_after_read else 0,
                password_hash,
                uploaded_by,
            ),
        )
        conn.commit()


def get_metadata(file_id: str) -> dict:
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            """SELECT filename, key_salt, nonce, expires_at, expired,
                      burn_after_read, password_hash, file_type
               FROM files WHERE id = ?""",
            (file_id,),
        )
        row = c.fetchone()
        if not row:
            return None
        return {
            "filename": row[0],
            "key_salt": row[1],
            "nonce": row[2],
            "expires_at": datetime.datetime.fromisoformat(row[3]) if isinstance(row[3], str) else row[3],
            "expired": bool(row[4]),
            "burn_after_read": bool(row[5]),
            "password_hash": row[6],
            "file_type": row[7] or "application/pdf",
        }


def mark_expired(file_id: str):
    """Mark the vault as expired. The key_salt becomes useless without the password."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE files SET key_salt = NULL, expired = 1 WHERE id = ?", (file_id,))
        conn.commit()


def list_user_files(user_email: str = None) -> list:
    """List files filtered by the uploading user's email."""
    with get_db() as conn:
        c = conn.cursor()
        if user_email:
            c.execute(
                """SELECT id, filename, expires_at, expired, burn_after_read,
                          original_size, created_at, uploaded_by
                   FROM files WHERE uploaded_by = ? ORDER BY created_at DESC""",
                (user_email,),
            )
        else:
            c.execute(
                """SELECT id, filename, expires_at, expired, burn_after_read,
                          original_size, created_at, uploaded_by
                   FROM files ORDER BY created_at DESC"""
            )
        rows = c.fetchall()
        return [
            {
                "id": row[0],
                "filename": row[1],
                "expires_at": row[2],
                "expired": bool(row[3]),
                "burn_after_read": bool(row[4]),
                "original_size": row[5] or 0,
                "created_at": row[6],
                "uploaded_by": row[7],
            }
            for row in rows
        ]


# --- AUDIT LOGGING ---

def log_access(file_id: str, action: str, ip_address: str = None, user_email: str = None, details: str = None):
    """Record an access event for audit trail."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO access_log (file_id, action, ip_address, user_email, details) VALUES (?, ?, ?, ?, ?)",
            (file_id, action, ip_address, user_email, details),
        )
        conn.commit()


def get_access_log(file_id: str = None) -> list:
    """Retrieve audit log entries."""
    with get_db() as conn:
        c = conn.cursor()
        if file_id:
            c.execute("SELECT file_id, action, ip_address, user_email, details, timestamp FROM access_log WHERE file_id = ? ORDER BY timestamp DESC", (file_id,))
        else:
            c.execute("SELECT file_id, action, ip_address, user_email, details, timestamp FROM access_log ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        return [
            {"file_id": row[0], "action": row[1], "ip": row[2], "user": row[3], "details": row[4], "timestamp": row[5]}
            for row in rows
        ]
