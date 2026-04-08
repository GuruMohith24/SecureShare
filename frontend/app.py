import streamlit as st
import streamlit.components.v1 as components
import requests
import base64
import re
import os
import datetime
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# Load secrets from .env (NEVER hardcode credentials)
load_dotenv()
API_URL = os.getenv("API_URL", "http://localhost:8000")
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8501")

SUPPORTED_EXTENSIONS = ["pdf", "docx", "doc", "xlsx", "xls", "csv",
                        "png", "jpg", "jpeg", "gif", "bmp",
                        "txt", "zip", "rar", "7z", "pptx", "ppt"]

st.set_page_config(page_title="SecureShare", page_icon="🛡️", layout="centered")

# Inject global CSS for a polished dark UI
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    .stApp { background: #0d1117; font-family: 'Inter', system-ui, sans-serif; }
    h1, h2, h3, h4, h5, h6 { color: #e6edf3 !important; font-family: 'Inter', system-ui, sans-serif; }

    .vault-badge {
        display:inline-block; padding:4px 12px; border-radius:20px;
        font-size:0.72rem; font-weight:700; letter-spacing:1.2px;
        text-transform: uppercase;
    }
    .badge-active  { background:#1a3a2a; color:#3fb950; border:1px solid #238636; }
    .badge-purged  { background:#3d1f1f; color:#f85149; border:1px solid #da3633; }
    .badge-burn    { background:#3d2e00; color:#d29922; border:1px solid #9e6a03; }
    .badge-locked  { background:#2d1f3d; color:#a371f7; border:1px solid #8957e5; }

    .timestamp-sub { color:#484f58; font-size:0.72rem; }
    .audit-row { padding:6px 10px; border-left:3px solid #30363d; margin-bottom:4px; font-size:0.78rem; }
    .audit-upload  { border-left-color:#3fb950; }
    .audit-download { border-left-color:#58a6ff; }
    .audit-failed  { border-left-color:#f85149; }
    .audit-burned  { border-left-color:#d29922; }

    /* Mobile responsive fix */
    @media (max-width: 768px) {
        .stApp h1 { font-size: 2.2rem !important; }
    }
</style>
""", unsafe_allow_html=True)


# ─── UTILITIES ────────────────────────────────────────────────

def validate_password(p):
    if len(p) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", p):
        return False, "Needs one uppercase letter."
    if not re.search(r"\d", p):
        return False, "Needs one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', p):
        return False, "Needs one special character."
    return True, ""


def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def time_ago(iso_str: str) -> str:
    """Friendly time-ago string from an ISO timestamp."""
    try:
        dt = datetime.datetime.fromisoformat(iso_str)
        delta = datetime.datetime.now() - dt
        if delta.total_seconds() < 60:
            return "just now"
        elif delta.total_seconds() < 3600:
            return f"{int(delta.total_seconds() // 60)}m ago"
        elif delta.total_seconds() < 86400:
            return f"{int(delta.total_seconds() // 3600)}h ago"
        else:
            return f"{int(delta.days)}d ago"
    except Exception:
        return ""


def get_file_icon(filename: str) -> str:
    """Return an emoji for a file type."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    icons = {
        "pdf": "📄", "docx": "📝", "doc": "📝", "xlsx": "📊", "xls": "📊",
        "csv": "📊", "pptx": "📽️", "ppt": "📽️", "txt": "📃",
        "png": "🖼️", "jpg": "🖼️", "jpeg": "🖼️", "gif": "🖼️", "bmp": "🖼️",
        "zip": "📦", "rar": "📦", "7z": "📦",
    }
    return icons.get(ext, "📄")


# ─── OAUTH CONFIG ─────────────────────────────────────────────

client_config = {
    "web": {
        "client_id": CLIENT_ID,
        "project_id": "secureshare-ai",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": CLIENT_SECRET,
        "redirect_uris": [REDIRECT_URI],
    }
}

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


def get_google_auth_url():
    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    url, _ = flow.authorization_url(access_type="offline")
    return url


# ─── HANDLE OAUTH CALLBACK (ONCE) ────────────────────────────

if "code" in st.query_params and "user" not in st.session_state:
    try:
        flow = Flow.from_client_config(client_config, scopes=SCOPES)
        flow.redirect_uri = REDIRECT_URI
        flow.fetch_token(code=st.query_params["code"])
        st.session_state.user = id_token.verify_oauth2_token(
            flow.credentials.id_token, google_requests.Request(), CLIENT_ID
        )
        st.query_params.clear()
        st.rerun()
    except Exception:
        if "user" not in st.session_state:
            st.error("Login link expired. Try again.")


# ─── SHARED HEADER ────────────────────────────────────────────

st.markdown(
    '<h1 style="text-align:center; font-size:3.5rem; letter-spacing:-2px; margin-bottom:0;">SECURESHARE</h1>',
    unsafe_allow_html=True,
)
st.markdown(
    '<p style="text-align:center; color:#58a6ff; margin-bottom:40px;">Secure, Ephemeral & Professional Document Transit</p>',
    unsafe_allow_html=True,
)


# ═════════════════════════════════════════════════════════════
# 1. RECIPIENT MODE — Vault Unlock & Viewer
# ═════════════════════════════════════════════════════════════

if "file_id" in st.query_params:
    file_id = st.query_params["file_id"]
    if "view_auth" not in st.session_state:
        st.session_state.view_auth = False

    if not st.session_state.view_auth:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.container(border=True):
                st.subheader("🔒 Vault Access")
                st.write("This document is vault-protected. Enter the Security Key to decrypt.")
                tk = st.text_input("Security Key", type="password")
                if st.button("Unlock Document", type="primary", use_container_width=True):
                    if tk:
                        st.session_state.view_key = tk
                        st.session_state.view_auth = True
                        st.rerun()
                    else:
                        st.warning("Key is mandatory.")
    else:
        try:
            res = requests.get(
                f"{API_URL}/download/{file_id}",
                params={"password": st.session_state.view_key},
            )
            if res.status_code == 200:
                b64 = base64.b64encode(res.content).decode("utf-8")
                doc_name = res.headers.get("X-Filename", "Document")
                file_type = res.headers.get("X-File-Type", "application/pdf")

                # Calculate remaining seconds
                expires_at_str = res.headers.get("X-Expires-At", "")
                remaining_secs = 0
                try:
                    expires_at = datetime.datetime.fromisoformat(expires_at_str)
                    remaining_secs = max(0, int((expires_at - datetime.datetime.now()).total_seconds()))
                except Exception:
                    remaining_secs = 300

                # Document name badge with file icon
                icon = get_file_icon(doc_name)
                st.markdown(
                    f'<p style="text-align:center; color:#8b949e; margin-bottom:5px;">{icon} <b style="color:#e6edf3;">{doc_name}</b></p>',
                    unsafe_allow_html=True,
                )

                # Live countdown timer with auto-redirect on expiry
                timer_html = f"""
                <div id="timer-box" style="
                    text-align:center; padding:14px 20px;
                    background:linear-gradient(135deg, #0d1117, #161b22);
                    border:1px solid #30363d; border-radius:12px;
                    font-family:'Inter','Segoe UI',system-ui,sans-serif;">
                    <span style="color:#8b949e; font-size:0.85rem; text-transform:uppercase; letter-spacing:2px;">
                        ⏱️ Vault Self-Destructs In
                    </span><br>
                    <span id="cd" style="font-size:2.8rem; font-weight:800; color:#ff6b6b; letter-spacing:4px;">
                        {remaining_secs // 60}:{remaining_secs % 60:02d}
                    </span>
                </div>
                <script>
                    let r = {remaining_secs};
                    const el = document.getElementById('cd');
                    const box = document.getElementById('timer-box');
                    function tick() {{
                        if (r <= 0) {{
                            el.innerText = 'EXPIRED';
                            el.style.color = '#f85149';
                            box.style.borderColor = '#f85149';
                            setTimeout(function() {{
                                window.top.location.href = '{REDIRECT_URI}';
                            }}, 3000);
                            return;
                        }}
                        r--;
                        const m = Math.floor(r / 60);
                        const s = r % 60;
                        el.innerText = m + ':' + (s < 10 ? '0' : '') + s;
                        if (r < 60) {{ el.style.animation = 'pulse 1s infinite'; }}
                        setTimeout(tick, 1000);
                    }}
                    tick();
                </script>
                <style>
                    @keyframes pulse {{
                        0%, 100% {{ opacity: 1; }}
                        50% {{ opacity: 0.4; }}
                    }}
                </style>
                """
                components.html(timer_html, height=110)

                # Watermark overlay template
                watermark_divs = ""
                positions = [
                    (5, 10), (5, 55), (25, -5), (25, 40), (25, 80),
                    (45, 15), (45, 60), (65, -5), (65, 40), (65, 80),
                    (85, 10), (85, 55),
                ]
                for top, left in positions:
                    watermark_divs += f"""<div style="position:absolute; top:{top}%; left:{left}%;
                        transform:rotate(-35deg); font-size:1.4rem; opacity:0.06;
                        color:white; font-weight:700; white-space:nowrap;
                        letter-spacing:6px; pointer-events:none; user-select:none;">
                        SECURESHARE &bull; CONFIDENTIAL</div>"""

                # Smart viewer based on file type
                if file_type.startswith("image/"):
                    # IMAGE viewer
                    # IMAGE viewer — Uses components for JS self-destruct
                    img_html = f"""
                    <div id="img-wrap" style="position:relative; width:100%; border-radius:12px; overflow:hidden; border:1px solid #30363d; background:white;">
                        <img src="data:{file_type};base64,{b64}" style="width:100%; display:block; object-fit:contain;">
                        <div style="position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none; z-index:10; overflow:hidden;">
                            {watermark_divs}
                        </div>
                    </div>
                    <script>
                        setTimeout(function() {{
                            document.getElementById('img-wrap').innerHTML = 
                                '<div style="padding:100px 20px; text-align:center; font-family:sans-serif; background:#0d1117;">' +
                                '<h2 style="color:#f85149; font-size:2rem; margin:0;">VAULT EXPIRED</h2>' +
                                '<p style="color:#8b949e;">The image has been securely destroyed.</p></div>';
                        }}, {max(0, remaining_secs)} * 1000);
                    </script>
                    """
                    components.html(img_html, height=700, scrolling=True)

                elif file_type == "application/pdf":
                    # PDF viewer — PDF.js canvas renderer (works in all browsers)
                    pdf_html = f"""
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
                    <style>
                        #pdf-wrap {{
                            position: relative; width: 100%; border-radius: 12px;
                            overflow-y: auto; border: 1px solid #30363d; background: #fff;
                        }}
                        #pdf-wrap canvas {{ width: 100%; display: block; }}
                        .wm {{
                            position: absolute; transform: rotate(-35deg);
                            font-size: 1.4rem; opacity: 0.07; color: #000;
                            font-weight: 700; white-space: nowrap; letter-spacing: 6px;
                            pointer-events: none; user-select: none;
                        }}
                    </style>
                    <div id="pdf-wrap"></div>
                    <script>
                        // Self-destruct the viewer when the timer expires
                        setTimeout(function() {{
                            document.getElementById('pdf-wrap').innerHTML = 
                                '<div style="padding:100px 20px; text-align:center; font-family:sans-serif;">' +
                                '<h2 style="color:#f85149; font-size:2rem; margin:0;">VAULT EXPIRED</h2>' +
                                '<p style="color:#8b949e;">The document has been securely destroyed.</p></div>';
                        }}, {max(0, remaining_secs)} * 1000);

                        pdfjsLib.GlobalWorkerOptions.workerSrc =
                            'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

                        const raw = atob('{b64}');
                        const arr = new Uint8Array(raw.length);
                        for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);

                        const wrap = document.getElementById('pdf-wrap');

                        pdfjsLib.getDocument({{data: arr}}).promise.then(async function(pdf) {{
                            for (let p = 1; p <= pdf.numPages; p++) {{
                                const page = await pdf.getPage(p);
                                const vp = page.getViewport({{scale: 1.8}});
                                const canvas = document.createElement('canvas');
                                canvas.width = vp.width;
                                canvas.height = vp.height;
                                wrap.appendChild(canvas);
                                await page.render({{canvasContext: canvas.getContext('2d'), viewport: vp}}).promise;
                            }}

                            // Add watermarks after render
                            const positions = [
                                [5,10],[5,55],[25,-5],[25,40],[25,80],
                                [45,15],[45,60],[65,-5],[65,40],[65,80],[85,10],[85,55]
                            ];
                            positions.forEach(function(pos) {{
                                const d = document.createElement('div');
                                d.className = 'wm';
                                d.style.top = pos[0] + '%';
                                d.style.left = pos[1] + '%';
                                d.innerHTML = 'SECURESHARE &bull; CONFIDENTIAL';
                                wrap.appendChild(d);
                            }});
                        }});
                    </script>
                    """
                    components.html(pdf_html, height=900, scrolling=True)

                elif file_type == "text/plain" or file_type == "text/csv":
                    # TEXT viewer
                    try:
                        text_content = res.content.decode("utf-8")
                    except Exception:
                        text_content = res.content.decode("latin-1")
                    st.code(text_content[:50000], language="text")

                else:
                    # BINARY FILES (docx, xlsx, zip, etc.) — download only
                    st.info(f"📦 This file type (`{file_type}`) cannot be previewed inline. Use the download button below.")
                    st.download_button(
                        label=f"⬇️ Download {doc_name}",
                        data=res.content,
                        file_name=doc_name,
                        mime=file_type,
                        use_container_width=True,
                    )

                if st.button("← Dismiss Viewer", type="secondary"):
                    st.session_state.view_auth = False
                    st.rerun()

            elif res.status_code == 429:
                st.error("🚫 Too many failed attempts! You are locked out for 10 minutes.")
                st.session_state.view_auth = False
            elif res.status_code == 410:
                st.error("🔥 This vault has expired or been purged after viewing.")
            elif res.status_code == 401:
                error_msg = "🔒 Incorrect Security Key."
                try:
                    detail = res.json().get("detail", "")
                    if detail:
                        error_msg = f"🔒 {detail}"
                except Exception:
                    pass
                st.error(error_msg)
                st.session_state.view_auth = False
            else:
                st.error("Incorrect Key or Document Expired.")
        except requests.exceptions.ConnectionError:
            st.error("⚠️ Cannot reach SecureShare API. Is the backend server running?")
        except Exception as e:
            st.error(f"Vault Connection Fault: {e}")
    st.stop()


# ═════════════════════════════════════════════════════════════
# 2. SENDER LOGIN GATE & LANDING PAGE
# ═════════════════════════════════════════════════════════════

if "user" not in st.session_state:
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Feature Banner
    c1, c2, c3 = st.columns(3)
    with c1:
        st.info("**🔐 AES-256-GCM Vault**\n\nMilitary-grade authenticated encryption. Your decrypted files never touch physical disks.")
    with c2:
        st.warning("**🔥 Burn After Read**\n\nKeys are physically wiped when the vault expires or is viewed. Data recovery is cryptographically impossible.")
    with c3:
        st.success("**📋 Immutable Audit Logs**\n\nMonitor every vault access attempt, failed brute force attacks, and payload detonations in real-time.")
        
    st.markdown("<br><hr style='border:1px solid #30363d'><br>", unsafe_allow_html=True)
    
    # Login Box
    col_l, col_m, col_r = st.columns([1, 2, 1])
    with col_m:
        with st.container(border=True):
            st.markdown('<div style="text-align:center">', unsafe_allow_html=True)
            st.write("### 🔑 Authorized Personnel")
            st.caption("Authenticate to provision secure vaults and track transmissions.")
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("LOG IN WITH GOOGLE SSO", type="primary", use_container_width=True):
                st.markdown(
                    f'<meta http-equiv="refresh" content="0; url={get_google_auth_url()}">',
                    unsafe_allow_html=True,
                )
            st.markdown("</div>", unsafe_allow_html=True)
            
    st.markdown("<br><br><p style='text-align:center; color:#484f58; font-size:0.8rem;'>Protected by PBKDF2 Hashing • Ephemeral Storage • Zero Tracking</p>", unsafe_allow_html=True)
    st.stop()


# ═════════════════════════════════════════════════════════════
# 3. SENDER DASHBOARD (post-login)
# ═════════════════════════════════════════════════════════════

user_email = st.session_state.user["email"]
user_name = st.session_state.user["name"]

st.sidebar.title("🛡️ SecureShare")
st.sidebar.write(f"**{user_name}**")
st.sidebar.caption(user_email)
if st.sidebar.button("Logout", use_container_width=True):
    del st.session_state.user
    st.rerun()

tab1, tab2, tab3 = st.tabs(["🚀 NEW VAULT", "🕒 VAULT HISTORY", "📋 AUDIT LOG"])

# ─── TAB 1: Create New Vault ──────────────────────────────────
with tab1:
    with st.container(border=True):
        st.write("### Prepare Encryption Vault")
        upl = st.file_uploader(
            "Select Documentation",
            type=SUPPORTED_EXTENSIONS,
            label_visibility="collapsed",
            help=f"Supported: {', '.join(SUPPORTED_EXTENSIONS).upper()}",
        )

        pwd = st.text_input("Encryption Key", type="password", help="8+ chars, Uppercase, Digit, Special.")

        c1, c2 = st.columns(2)
        with c1:
            dur = st.select_slider("Persistence (Minutes)", options=[1, 5, 10, 30, 60], value=5)
        with c2:
            once = st.toggle(
                "Burn After View",
                value=True,
                help="Automatically purge the vault after the recipient first opens it.",
            )

        if st.button("INITIATE SECURE VAULT", type="primary", use_container_width=True):
            if not upl or not pwd:
                st.error("Please provide both a file and an encryption key.")
            else:
                valid, msg = validate_password(pwd)
                if not valid:
                    st.error(f"Weak Key: {msg}")
                else:
                    try:
                        # Determine MIME type from filename
                        ext = upl.name.rsplit(".", 1)[-1].lower() if "." in upl.name else ""
                        mime_map = {
                            "pdf": "application/pdf",
                            "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                            "gif": "image/gif", "bmp": "image/bmp",
                            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                            "txt": "text/plain", "csv": "text/csv",
                            "zip": "application/zip",
                        }
                        content_type = mime_map.get(ext, "application/octet-stream")

                        resp = requests.post(
                            f"{API_URL}/upload",
                            files={"file": (upl.name, upl.getvalue(), content_type)},
                            data={
                                "expiry_minutes": int(dur),
                                "burn_after_read": str(once).lower(),
                                "password": pwd,
                                "uploaded_by": user_email,
                            },
                        )
                        if resp.status_code == 200:
                            st.session_state.vault_link = (
                                f"http://localhost:8501/?file_id={resp.json()['file_id']}"
                            )
                            st.success("✅ VAULT SECURELY ACTIVATED!")
                        elif resp.status_code == 413:
                            st.error("📦 File is too large. Maximum upload size is 200 MB.")
                        elif resp.status_code == 400:
                            detail = "Upload rejected."
                            try:
                                detail = resp.json().get("detail", detail)
                            except Exception:
                                pass
                            st.error(f"⚠️ {detail}")
                        else:
                            st.error("The vault could not be activated. Server reported error.")
                    except requests.exceptions.ConnectionError:
                        st.error("⚠️ Cannot reach SecureShare API. Is the backend server running?")
                    except Exception:
                        st.error("System fault during transmission.")

    if "vault_link" in st.session_state:
        with st.container(border=True):
            st.markdown("##### 🔗 Public Retrieval Link")
            st.code(st.session_state.vault_link, language="text")
            st.info("The link above is useless without the Security Key you provided.")


# ─── TAB 2: Vault History (per-user isolation) ────────────────
with tab2:
    try:
        r = requests.get(f"{API_URL}/files", params={"user_email": user_email})
        if r.status_code == 200:
            vault_list = r.json()
            if not vault_list:
                st.info("You haven't created any vaults yet.")
            else:
                st.caption(f"Showing {len(vault_list)} vault(s) created by **{user_email}**")
                for item in vault_list:
                    with st.container(border=True):
                        c_file, c_meta, c_stat, c_link = st.columns([3, 2, 2, 2])

                        icon = get_file_icon(item["filename"])
                        c_file.write(f"{icon} **{item['filename']}**")
                        created_str = time_ago(item.get("created_at", ""))
                        c_file.markdown(
                            f'<span class="timestamp-sub">{created_str}</span>',
                            unsafe_allow_html=True,
                        )

                        size_str = format_size(item.get("original_size", 0))
                        c_meta.caption(f"📦 {size_str}")

                        # Expiry remaining
                        try:
                            exp_dt = datetime.datetime.fromisoformat(item["expires_at"])
                            remaining = exp_dt - datetime.datetime.now()
                            if remaining.total_seconds() > 0 and not item["expired"]:
                                mins_left = int(remaining.total_seconds() // 60)
                                c_meta.caption(f"⏱️ {mins_left}m left")
                        except Exception:
                            pass

                        if item["expired"]:
                            c_stat.markdown(
                                '<span class="vault-badge badge-purged">PURGED</span>',
                                unsafe_allow_html=True,
                            )
                        elif item.get("burn_after_read"):
                            c_stat.markdown(
                                '<span class="vault-badge badge-burn">🔥 BURN</span>',
                                unsafe_allow_html=True,
                            )
                        else:
                            c_stat.markdown(
                                '<span class="vault-badge badge-active">ACTIVE</span>',
                                unsafe_allow_html=True,
                            )

                        if not item["expired"] and c_link.button(
                            "Get Link", key=item["id"], use_container_width=True
                        ):
                            st.code(f"http://localhost:8501/?file_id={item['id']}")
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot reach SecureShare API. Is the backend server running?")
    except Exception:
        st.error("Unable to load history at this time.")


# ─── TAB 3: Audit Log ────────────────────────────────────────
with tab3:
    st.write("### 📋 Access Audit Trail")
    st.caption("Every upload, download, failed attempt, and burn event is logged.")

    try:
        # Fetch all vaults to get their IDs and audit logs
        r = requests.get(f"{API_URL}/files", params={"user_email": user_email})
        if r.status_code == 200:
            vaults = r.json()
            if not vaults:
                st.info("No vaults yet — audit log is empty.")
            else:
                all_logs = []
                for vault in vaults:
                    try:
                        aud = requests.get(f"{API_URL}/audit/{vault['id']}")
                        if aud.status_code == 200:
                            for entry in aud.json():
                                entry["vault_name"] = vault["filename"]
                                all_logs.append(entry)
                    except Exception:
                        pass

                if not all_logs:
                    st.info("No audit entries recorded yet.")
                else:
                    # Sort by timestamp descending
                    all_logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                    for entry in all_logs[:50]:
                        action = entry.get("action", "")
                        css_class = "audit-row"
                        if action == "upload":
                            css_class += " audit-upload"
                            icon = "📤"
                        elif action == "download":
                            css_class += " audit-download"
                            icon = "📥"
                        elif action in ("failed_unlock", "rate_limited"):
                            css_class += " audit-failed"
                            icon = "🚫"
                        elif action == "burned":
                            css_class += " audit-burned"
                            icon = "🔥"
                        else:
                            icon = "📌"

                        ts = entry.get("timestamp", "")[:19]
                        ip = entry.get("ip", "—")
                        details = entry.get("details", "")
                        vault_name = entry.get("vault_name", "Unknown")

                        st.markdown(
                            f'<div class="{css_class}">'
                            f'{icon} <b>{action.upper()}</b> — {vault_name} '
                            f'<span class="timestamp-sub">| {ts} | IP: {ip}</span>'
                            f'{"<br><small>" + details + "</small>" if details else ""}'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot reach SecureShare API. Is the backend server running?")
    except Exception:
        st.error("Unable to load audit log.")
