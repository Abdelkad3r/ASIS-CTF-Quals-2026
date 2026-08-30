#!/usr/bin/env python3
"""
Sultan Online CTF Web Application
Interactive Challenge Server
"""

import hmac
import os
import secrets
import string
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from flask import (
    Flask,
    Response,
    jsonify,
    make_response,
    render_template,
    request,
)

from crypto_engine import encrypt_sultan

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# --------------------------------------------------------------------------
# Configuration & Security Parameters
# --------------------------------------------------------------------------
SESSION_TTL_SECONDS = 20 * 60  # 20 minutes
MAX_ENCRYPTIONS_PER_SESSION = 500  # Prevent DoS / Resource exhaustion
MAX_SESSIONS_STORED = 10000

# Secret length range: randomly between 28 and 32 characters
MIN_SECRET_LENGTH = 28
MAX_SECRET_LENGTH = 32

# Flag loaded from environment variable for secure deployment
FLAG = os.environ.get("FLAG", "ASIS{test_flag_for_local_development}")

# --------------------------------------------------------------------------
# Thread-safe In-Memory Session Store
# --------------------------------------------------------------------------
@dataclass
class UserSession:
    session_id: str
    secret_string: str
    created_at: float
    last_accessed: float
    enc_count: int = 0
    solved: bool = False

    @property
    def expires_at(self) -> float:
        return self.created_at + SESSION_TTL_SECONDS

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def remaining_seconds(self) -> int:
        rem = int(self.expires_at - time.time())
        return max(0, rem)


sessions_lock = threading.Lock()
sessions: Dict[str, UserSession] = {}

def generate_random_string() -> str:
    # Random length between 28 and 32 characters
    length = secrets.randbelow(MAX_SECRET_LENGTH - MIN_SECRET_LENGTH + 1) + MIN_SECRET_LENGTH
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def get_or_create_session(token: Optional[str] = None) -> Tuple[UserSession, bool]:
    """Returns (UserSession, was_expired_boolean)."""
    now = time.time()
    with sessions_lock:
        # Periodic cleanup of expired / stale sessions
        if len(sessions) > MAX_SESSIONS_STORED or len(sessions) % 50 == 0:
            stale_keys = [k for k, s in sessions.items() if now - s.created_at > SESSION_TTL_SECONDS]
            for k in stale_keys:
                sessions.pop(k, None)

        if token and token in sessions:
            sess = sessions[token]
            sess.last_accessed = now
            if not sess.is_expired:
                return sess, False
            # Session expired: regenerate secret with new random length [28, 32] and restart timer
            sess.secret_string = generate_random_string()
            sess.created_at = now
            sess.last_accessed = now
            sess.enc_count = 0
            sess.solved = False
            return sess, True

        # Generate cryptographically secure internal token
        new_token = secrets.token_urlsafe(32)
        new_sess = UserSession(
            session_id=new_token,
            secret_string=generate_random_string(),
            created_at=now,
            last_accessed=now,
        )
        sessions[new_token] = new_sess
        return new_sess, False

def resolve_session() -> Tuple[UserSession, bool]:
    token = request.cookies.get("sultan_session")
    return get_or_create_session(token)

def attach_session_cookie(response: Response, session_id: str) -> Response:
    response.set_cookie(
        "sultan_session",
        session_id,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="Lax",
    )
    return response

# --------------------------------------------------------------------------
# Security Headers
# --------------------------------------------------------------------------
@app.after_request
def set_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# --------------------------------------------------------------------------
# Routes & Endpoints
# --------------------------------------------------------------------------
@app.route("/")
def index():
    sess, _ = resolve_session()
    resp = make_response(render_template(
        "index.html",
        remaining_seconds=sess.remaining_seconds,
        enc_count=sess.enc_count,
        solved=sess.solved,
    ))
    return attach_session_cookie(resp, sess.session_id)

@app.route("/api/session", methods=["GET"])
def api_session():
    sess, was_expired = resolve_session()
    resp = jsonify({
        "remaining_seconds": sess.remaining_seconds,
        "ttl_seconds": SESSION_TTL_SECONDS,
        "enc_count": sess.enc_count,
        "solved": sess.solved,
        "expired": was_expired,
    })
    return attach_session_cookie(resp, sess.session_id)

@app.route("/api/encrypt", methods=["GET"])
@app.route("/download", methods=["GET"])
def api_encrypt():
    sess, was_expired = resolve_session()
    
    with sessions_lock:
        if sess.enc_count >= MAX_ENCRYPTIONS_PER_SESSION:
            return jsonify({
                "success": False,
                "error": "Request limit exceeded for this session. Please reset your session."
            }), 429

        sess.enc_count += 1
        secret_bytes = sess.secret_string.encode("utf-8")

    # Fast in-memory Sultan encryption
    encrypted_blob = encrypt_sultan(secret_bytes)

    resp = make_response(encrypted_blob)
    resp.headers["Content-Type"] = "application/octet-stream"
    resp.headers["Content-Disposition"] = 'attachment; filename="secret.enc"'
    resp.headers["X-Encryptions-Count"] = str(sess.enc_count)
    resp.headers["X-Remaining-Seconds"] = str(sess.remaining_seconds)
    return attach_session_cookie(resp, sess.session_id)

@app.route("/api/verify", methods=["POST"])
def api_verify():
    sess, was_expired = resolve_session()
    data = request.get_json(silent=True) or request.form
    guess = data.get("guess", "").strip()

    if not guess:
        return jsonify({"success": False, "message": "Please provide a guess string."}), 400

    if len(guess) > 200:
        return jsonify({"success": False, "message": "Guess too long."}), 400

    if was_expired:
        resp = jsonify({
            "success": False,
            "expired": True,
            "message": "Session expired (> 20 minutes). A new secret string has been generated.",
        })
        return attach_session_cookie(resp, sess.session_id), 400

    # Constant-time comparison to prevent timing attacks
    if hmac.compare_digest(guess, sess.secret_string):
        with sessions_lock:
            sess.solved = True
        resp = jsonify({
            "success": True,
            "message": "Congratulations! Secret verified correctly.",
            "flag": FLAG,
        })
        return attach_session_cookie(resp, sess.session_id)

    resp = jsonify({
        "success": False,
        "message": "Incorrect secret string. Keep analyzing the transcripts!",
    })
    return attach_session_cookie(resp, sess.session_id), 400

@app.route("/api/reset", methods=["POST"])
def api_reset():
    now = time.time()
    with sessions_lock:
        new_token = secrets.token_urlsafe(32)
        new_sess = UserSession(
            session_id=new_token,
            secret_string=generate_random_string(),
            created_at=now,
            last_accessed=now,
        )
        sessions[new_token] = new_sess

    resp = jsonify({
        "success": True,
        "message": "Session reset successfully with a new 20-minute secret.",
        "remaining_seconds": SESSION_TTL_SECONDS,
    })
    return attach_session_cookie(resp, new_sess.session_id)

# --------------------------------------------------------------------------
# Main Entry Point
# --------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Sultan CTF WebApp on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
