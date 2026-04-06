from fastapi import FastAPI, UploadFile, Form, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from collections import defaultdict
import os
import uuid
import time
import datetime

from .database import init_db, store_metadata, get_metadata, mark_expired, list_user_files, get_db, log_access
from .crypto import derive_key, encrypt_file, decrypt_file, hash_password, verify_password

UPLOAD_DIR = "backend/uploads"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "200")) * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".txt", ".zip", ".rar", ".7z", ".pptx", ".ppt",
}

MIME_MAP = {
    ".pdf": "application/pdf",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".bmp": "image/bmp",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain", ".csv": "text/csv",
    ".zip": "application/zip", ".rar": "application/x-rar-compressed",
}

scheduler = BackgroundScheduler()

# --- IN-MEMORY RATE LIMITER ---
_fail_tracker: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX = 5          # max failed attempts
RATE_LIMIT_WINDOW = 600     # 10-minute window


def _is_rate_limited(key: str) -> bool:
    now = time.time()
    _fail_tracker[key] = [t for t in _fail_tracker[key] if now - t < RATE_LIMIT_WINDOW]
    return len(_fail_tracker[key]) >= RATE_LIMIT_MAX


def _record_fail(key: str):
    _fail_tracker[key].append(time.time())


def cleanup_expired():
    """Scheduled task: delete encrypted files and wipe salts for expired vaults."""
    now = datetime.datetime.now()
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM files WHERE expires_at < ? AND expired = 0", (now.isoformat(),))
        expired_files = c.fetchall()
        for row in expired_files:
            file_id = row[0]
            filepath = os.path.join(UPLOAD_DIR, file_id)
            if os.path.exists(filepath):
                os.remove(filepath)
                print(f"[CLEANUP] Deleted encrypted file: {file_id}")
            c.execute("UPDATE files SET key_salt = NULL, expired = 1 WHERE id = ?", (file_id,))
            print(f"[CLEANUP] Salt destroyed: {file_id}")
        conn.commit()


@asynccontextmanager
async def lifespan(application: FastAPI):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    init_db()
    scheduler.add_job(cleanup_expired, "interval", minutes=1)
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(title="SecureShare API", version="4.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://localhost:8502", "http://127.0.0.1:8501"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile,
    expiry_minutes: int = Form(...),
    burn_after_read: bool = Form(False),
    password: str = Form(...),
    uploaded_by: str = Form(None),
):
    if expiry_minutes <= 0:
        raise HTTPException(status_code=400, detail="Expiry minutes must be greater than 0")

    if not password or len(password) < 8:
        raise HTTPException(status_code=400, detail="Password is required and must be at least 8 characters.")

    # Validate file extension
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"File type '{ext}' is not allowed. Supported: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    content = await file.read()

    if len(content) > MAX_UPLOAD_BYTES:
        max_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        raise HTTPException(status_code=413, detail=f"File too large. Maximum: {max_mb} MB.")

    file_id = str(uuid.uuid4())

    # ── E2E: Derive AES key from password (key is NEVER stored) ──
    aes_key, key_salt = derive_key(password)
    encrypted_data, nonce = encrypt_file(content, aes_key)

    # Wipe the key from memory immediately after encryption
    del aes_key

    filepath = os.path.join(UPLOAD_DIR, file_id)
    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    expires_at = datetime.datetime.now() + datetime.timedelta(minutes=expiry_minutes)
    pwd_hash = hash_password(password)
    file_type = MIME_MAP.get(ext, "application/octet-stream")

    # Store ONLY the salt — the key itself is never persisted
    store_metadata(
        file_id, file.filename, expires_at, key_salt, nonce,
        burn_after_read, pwd_hash,
        original_size=len(content),
        uploaded_by=uploaded_by,
        file_type=file_type,
    )

    # Audit log
    client_ip = request.client.host if request.client else "unknown"
    log_access(file_id, "upload", client_ip, uploaded_by, f"filename={file.filename}, size={len(content)}, expiry={expiry_minutes}m, e2e=true")

    return {
        "file_id": file_id,
        "filename": file.filename,
        "expires_at": expires_at.isoformat(),
        "burn_after_read": burn_after_read,
        "password_protected": True,
        "e2e_encrypted": True,
    }


@app.get("/download/{file_id}")
async def download_file(request: Request, file_id: str, password: str = None):
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{file_id}:{client_ip}"

    # Rate limiting check
    if _is_rate_limited(rate_key):
        log_access(file_id, "rate_limited", client_ip, details="Too many failed attempts")
        raise HTTPException(status_code=429, detail="Too many failed attempts. Please wait 10 minutes before trying again.")

    metadata = get_metadata(file_id)
    if not metadata:
        raise HTTPException(status_code=404, detail="File not found")

    if metadata["expired"] or not metadata["key_salt"]:
        raise HTTPException(status_code=410, detail="File has expired and is permanently inaccessible")

    # Verify password hash first (fast check before expensive key derivation)
    if metadata["password_hash"]:
        if not password or not verify_password(password, metadata["password_hash"]):
            _record_fail(rate_key)
            remaining = RATE_LIMIT_MAX - len([t for t in _fail_tracker[rate_key] if time.time() - t < RATE_LIMIT_WINDOW])
            log_access(file_id, "failed_unlock", client_ip, details=f"Wrong password, {remaining} attempts left")
            raise HTTPException(status_code=401, detail=f"Invalid password. {remaining} attempts remaining before lockout.")

    # Double-check expiry
    now = datetime.datetime.now()
    if metadata["expires_at"] < now:
        mark_expired(file_id)
        filepath = os.path.join(UPLOAD_DIR, file_id)
        if os.path.exists(filepath):
            os.remove(filepath)
        raise HTTPException(status_code=410, detail="File has expired")

    # Read encrypted blob
    filepath = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File content not found on disk")

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    # ── E2E: Re-derive the AES key from password + stored salt ──
    try:
        aes_key, _ = derive_key(password, metadata["key_salt"])
        plaintext = decrypt_file(encrypted_data, aes_key, metadata["nonce"])
        del aes_key  # Wipe key from memory immediately
    except Exception as e:
        log_access(file_id, "failed_unlock", client_ip, details=f"Decryption failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Decryption failed. The vault may be corrupted.")

    # Audit: successful download
    log_access(file_id, "download", client_ip, details=f"filename={metadata['filename']}, e2e=true")

    # Burn after read
    if metadata["burn_after_read"]:
        print(f"[BURN] Self-destructing vault: {file_id}")
        mark_expired(file_id)
        if os.path.exists(filepath):
            os.remove(filepath)
        log_access(file_id, "burned", client_ip, details="Destroyed after first view")

    return Response(
        content=plaintext,
        media_type=metadata.get("file_type", "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{metadata["filename"]}"',
            "X-Filename": metadata["filename"],
            "X-File-Type": metadata.get("file_type", "application/octet-stream"),
            "X-Expires-At": metadata["expires_at"].isoformat()
            if hasattr(metadata["expires_at"], "isoformat")
            else str(metadata["expires_at"]),
            "X-E2E-Encrypted": "true",
        },
    )


@app.get("/files")
async def get_files(user_email: str = None):
    """Returns files filtered by user email for per-user isolation."""
    return list_user_files(user_email)


@app.get("/audit/{file_id}")
async def get_audit(file_id: str):
    """Returns audit log for a specific vault."""
    from .database import get_access_log
    return get_access_log(file_id)
