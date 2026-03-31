# 🛡️ SECURESHARE

**Secure, Ephemeral & Professional Document Transit**

SecureShare is a production-grade, ephemeral document sharing platform that lets you encrypt, vault, and share files via time-limited, password-protected links — with military-grade cryptographic security.

---

## ✨ Features

| Feature | Description |
|---|---|
| **AES-256-GCM Encryption** | Industry-standard authenticated encryption for all files |
| **PBKDF2 Password Hashing** | 100,000-iteration hashing with random salt — no plaintext passwords |
| **Burn After Read** | Self-destructs data immediately after first view |
| **Auto-Expiry** | Configurable timers (1–60 min) with background cleanup every 60s |
| **17+ File Types** | PDF, DOCX, XLSX, CSV, PNG, JPG, ZIP, TXT, PPTX, and more |
| **Smart Viewer** | Inline preview for PDFs and images; download for binaries |
| **Watermark Overlay** | Repeating diagonal "SECURESHARE • CONFIDENTIAL" on all previews |
| **Live Countdown Timer** | JS-powered auto-updating timer with red pulse at <60s |
| **Google OAuth 2.0** | Secure sender authentication via Google |
| **Per-User Isolation** | Each sender sees only their own vault history |
| **Rate Limiting** | 5 failed password attempts = 10-minute lockout |
| **Audit Logging** | Every upload, download, failed attempt, and burn is logged |
| **200MB Upload Limit** | Configurable via `MAX_UPLOAD_MB` environment variable |
| **Secure Delete** | SQLite `PRAGMA secure_delete` physically overwrites purged keys |

---

## 🏗️ Architecture

```
┌──────────────────────────┐       ┌────────────────────────────┐
│   Streamlit Frontend     │       │    FastAPI Backend          │
│   (Port 8501)            │ HTTP  │    (Port 8000)              │
│                          │◄─────►│                              │
│  • Google OAuth Login    │       │  • /upload → Encrypt + Store │
│  • File Upload UI        │       │  • /download/{id} → Decrypt  │
│  • Vault History (user)  │       │  • /files?user_email=...     │
│  • Audit Log Tab         │       │  • /audit/{file_id}          │
│  • Recipient Viewer      │       │  • Rate Limiting (in-memory) │
│  • Live Timer + Watermark│       │  • Background Cleanup Job    │
└──────────────────────────┘       └──────────┬─────────────────┘
                                              │
                             ┌────────────────┼────────────────┐
                             │                │                │
                        ┌────┴────┐    ┌──────┴─────┐   ┌─────┴──────┐
                        │ SQLite  │    │ Encrypted  │   │  Audit Log │
                        │ DB      │    │ File Store │   │  Table     │
                        │(schema) │    │ (uploads/) │   │(access_log)│
                        └─────────┘    └────────────┘   └────────────┘
```

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone <your-repo-url>
cd secureshare
python -m venv venv
.\venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file in the project root:

```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
REDIRECT_URI=http://localhost:8501
API_URL=http://localhost:8000
MAX_UPLOAD_MB=200
```

### 3. Run

```bash
# Terminal 1 — Backend
uvicorn backend.main:app --reload

# Terminal 2 — Frontend
streamlit run frontend/app.py
```

Open `http://localhost:8501` in your browser.

---

## 🔐 Security Model

```
Sender                                    Recipient
  │                                          │
  ├─ Login via Google OAuth ─────────────────│
  ├─ Upload file + set password + timer      │
  ├─ File encrypted with AES-256-GCM        │
  ├─ Password hashed with PBKDF2-SHA256     │
  ├─ Gets shareable link ────────────────────│
  ├─ Sends link + password (out-of-band) ──→ │
  │                                          ├─ Opens link
  │                                          ├─ Enters password (rate limited)
  │                                          ├─ Decrypted view with watermark
  │                                          ├─ Live countdown timer
  │                                          │
  │              ┌──────────────────┐        │
  │              │  💀 SELF-DESTRUCT │        │
  │              │  Key = NULL       │        │
  │              │  File = Deleted   │        │
  │              │  Data = GONE      │        │
  │              └──────────────────┘        │
```

---

## 📂 Project Structure

```
secureshare/
├── backend/
│   ├── __init__.py
│   ├── main.py           # FastAPI server + rate limiting + audit
│   ├── crypto.py         # AES-256-GCM + PBKDF2 password hashing
│   ├── database.py       # SQLite schema + per-user queries + audit log
│   └── uploads/          # Encrypted file blobs (auto-cleaned)
├── frontend/
│   ├── __init__.py
│   └── app.py            # Streamlit UI + OAuth + smart viewer
├── .env                  # Secrets (git-ignored)
├── requirements.txt
├── run.ps1               # Launcher script
└── README.md
```

---

## 🛑 Known Limitations

| Limitation | Severity | Workaround |
|---|---|---|
| No HTTPS (local dev) | High | Deploy with Nginx/Caddy for SSL |
| SQLite (single instance) | Medium | Migrate to PostgreSQL for scale |
| In-memory rate limiting | Low | Resets on server restart; use Redis for production |
| Screenshots bypass watermark | Inherent | Cannot be solved in browsers — use DRM for critical docs |

---

## 📜 License

MIT — build on it, break it, make it better.
