"""ユーザーID（復旧に使う英数字12文字）：作り方・照合の値・表示のための暗号化"""
import base64
import hashlib
import hmac
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import subkey

ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 0/O・1/I など紛らわしい字を除いた32文字
UID_LEN = 12                                       # 32種×12文字＝60ビット


def norm_code(s):
    return re.sub(r"[^A-Z0-9]", "", (s or "").upper())


def fmt_code(code):
    c = norm_code(code)
    return "-".join(c[i:i + 4] for i in range(0, len(c), 4))


def uid_lookup_hash(code):
    """照合用。検索に使うので決定的（ソルトなし）だが、サーバー秘密鍵つき HMAC なので、DB だけが漏れても ID を逆算・総当たりできない"""
    return hmac.new(subkey("uid-lookup"), norm_code(code).encode(), hashlib.sha256).hexdigest()


def encrypt_uid(code):
    nonce = secrets.token_bytes(12)
    return base64.b64encode(nonce + AESGCM(subkey("uid-enc")).encrypt(nonce, norm_code(code).encode(), b"uid")).decode()


def decrypt_uid(enc):
    raw = base64.b64decode(enc)
    return fmt_code(AESGCM(subkey("uid-enc")).decrypt(raw[:12], raw[12:], b"uid").decode())


def assign_user_id(conn, uid):
    """重ならないランダムなユーザーIDを付ける。表示の形（XXXX-XXXX-XXXX）で返す"""
    while True:
        code = "".join(secrets.choice(ID_ALPHABET) for _ in range(UID_LEN))
        h = uid_lookup_hash(code)
        if not conn.execute("SELECT 1 FROM users WHERE uid_hash=?", (h,)).fetchone():
            break
    conn.execute("UPDATE users SET uid_hash=?, uid_enc=? WHERE id=?", (h, encrypt_uid(code), uid))
    return fmt_code(code)


def user_code(u):
    return decrypt_uid(u["uid_enc"]) if u.get("uid_enc") else ""
