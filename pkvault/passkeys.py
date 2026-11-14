"""パスキーの道具：紐づけ先・チャレンジ・登録の設定と確かめ・保存。復旧キーの照合の形・作業証明・利用者の作成"""
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3

from flask import current_app, jsonify, request, session
from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, AuthenticatorTransport,
                                      PublicKeyCredentialDescriptor, PublicKeyCredentialHint, ResidentKeyRequirement,
                                      UserVerificationRequirement)

from .core import cfg, db, epoch, msg, now, subkey
from .guard import count_log, log_event, start_session
from .ids import assign_user_id

HINTS = {"hybrid": PublicKeyCredentialHint.HYBRID, "client-device": PublicKeyCredentialHint.CLIENT_DEVICE,
         "security-key": PublicKeyCredentialHint.SECURITY_KEY}
AUTH_RE = re.compile(r"^[0-9a-f]{64}$")           # 復旧キーから端末で作った確認用の値
WRAP_RE = re.compile(r"^[A-Za-z0-9_-]{60,200}$")  # 包み（版1バイト＋ノンス12バイト＋32バイトの鍵＋認証タグ16バイト）


def app_json(s):
    return current_app.response_class(s, mimetype="application/json")


# ---------------------------------------------------------------- 紐づけ先

def rp_id():
    """パスキーの紐づけ先。本番は設定の rp_id（ドメイン）で固定し、要求の Host ヘッダーには左右されない"""
    rid = cfg().rp_id or request.host.split(":")[0]
    try:
        ipaddress.ip_address(rid)
        return None  # IP アドレスではパスキーは使えない
    except ValueError:
        return rid


def expected_origin():
    c = cfg()
    if c.origin:
        return c.origin
    return f"https://{c.rp_id}" if c.rp_id else f"{request.scheme}://{request.host}"


def passkey_available():
    rid = rp_id()
    return bool(rid) and (request.is_secure or rid == "localhost")


def no_passkey():
    return jsonify(error=msg("no_passkey")), 400


# ---------------------------------------------------------------- チャレンジ（1回だけ使える）

def put_challenge(kind, challenge, **extra):
    session["chal"] = dict(k=kind, c=bytes_to_base64url(challenge), t=epoch(), **extra)


def take_challenge(kind):
    ch = session.pop("chal", None)
    if not ch or ch.get("k") != kind or epoch() - ch["t"] > cfg().challenge_ttl:
        return None
    # 使ったチャレンジはサーバーにも使用済みとして残す（クッキーは利用者の手元にあるので、前のクッキーと答えを盗み見て
    # 同じ要求を送り直されても、使った回数を数えないパスキー（同期するパスキー）で入られないように）
    try:
        db().execute("INSERT INTO pow_used(token, at) VALUES(?,?)", ("chal:" + str(ch.get("c")), epoch()))
    except sqlite3.IntegrityError:
        return None
    return ch


# ---------------------------------------------------------------- 登録

def transports(c):
    out = []
    for t in (c["transports"] or "").split(","):
        try:
            out.append(AuthenticatorTransport(t))
        except ValueError:
            pass
    return out or None


def registration_options(label, handle, exclude=(), hint=None):
    return generate_registration_options(
        rp_id=rp_id(), rp_name=cfg().app_name, user_name=label, user_display_name=label, user_id=handle,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,             # ユーザー名を入れずにログインできる
            user_verification=UserVerificationRequirement.REQUIRED),  # 端末のロック解除（生体認証や PIN）を必須
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]), transports=transports(c)) for c in exclude],
        hints=[HINTS[hint]] if isinstance(hint, str) and hint in HINTS else None,
    )


def verify_new_credential(cred_json, challenge_b64):
    return verify_registration_response(
        credential=cred_json, expected_challenge=base64url_to_bytes(challenge_b64),
        expected_rp_id=rp_id(), expected_origin=expected_origin(), require_user_verification=True)


def cred_dict(d):
    """送られてきたパスキーの答え（credential）。辞書でなければ空にする"""
    c = d.get("credential") if isinstance(d, dict) else None
    return c if isinstance(c, dict) else {}


def cred_transports(cred_json):
    r = cred_json.get("response")
    tr = r.get("transports") if isinstance(r, dict) else None
    return [t for t in tr if isinstance(t, str)] if isinstance(tr, list) else []


def is_security_key(cred_json):
    tr = set(cred_transports(cred_json))
    return cred_json.get("authenticatorAttachment") == "cross-platform" and "hybrid" not in tr and "internal" not in tr


def provider_name(aaguid):
    return cfg().providers.get((aaguid or "").lower(), "")


def device_name():
    ua = request.headers.get("User-Agent", "")
    for key, name in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("Macintosh", "Mac"),
                      ("Windows", "Windows"), ("CrOS", "Chromebook"), ("Linux", "Linux")):
        if key in ua:
            return name
    return "パスキー"


def store_credential(uid, v, cred_json, name, kind="", pending=False):
    """パスキーを保存し、付けた名前を返す（空なら保存先から自動で付ける）"""
    tr = ",".join(cred_transports(cred_json))[:200]
    aaguid = str(v.aaguid or "")
    via_qr = (cred_json.get("authenticatorAttachment") == "cross-platform") and "hybrid" in tr
    name = (name if isinstance(name, str) else "").strip() or provider_name(aaguid) or \
        ("セキュリティキー" if kind == "security-key" else "スマホ" if via_qr else device_name())
    db().execute("INSERT INTO credentials(id,user_id,public_key,sign_count,transports,name,backed_up,aaguid,kind,pending,created) "
                 "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 (bytes_to_base64url(v.credential_id), uid, v.credential_public_key, v.sign_count, tr,
                  name[:40], 1 if v.credential_backed_up else 0, aaguid, kind, 1 if pending else 0, now()))
    return name[:40]


# ---------------------------------------------------------------- 利用者

def user_public(u):
    return dict(name=u["name"], account=u["name"])


def create_user(name, handle):
    """名前は重複してよい（アカウントはユーザーIDで区別する）"""
    c = cfg()
    terms = f"{c.terms_version} {now()}" if c.terms_version else None
    cur = db().execute("INSERT INTO users(name,handle,session_days,terms_agreed,created) VALUES(?,?,?,?,?)",
                       (name, handle, c.session_days_default, terms, now()))
    code = assign_user_id(db(), cur.lastrowid)
    return dict(db().execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()), code


def welcome(user, code, cname, cred_id, event):
    """登録の完了。復旧キーとデータ鍵は、このあと端末が作って /vault/setup で包みを預ける"""
    log_event(user["id"], event, cname)
    start_session(user, "passkey", cred=cname, cred_id=cred_id)
    db().commit()
    return jsonify(ok=True, user=user_public(user), user_id=code)


# ---------------------------------------------------------------- 復旧キー

def recovery_digest(salt, auth):
    """復旧キーの照合の形。サーバーには「確認用の値」（復旧キーから端末で作った値）だけが届く。
    それを HMAC-SHA256(サーバー秘密鍵から作った鍵, ユーザーごとのソルト＋値) にして保存する。
    確認用の値からは、復旧キーもデータ鍵の包みを開ける値も計算できない"""
    return hmac.new(subkey("recovery"), f"{salt}:{auth}".encode(), hashlib.sha256).hexdigest()


def put_recovery(uid, auth, blob):
    """新しい復旧キー：照合の値と、そのキーで包んだデータ鍵を預かる（前のキーは使えなくなる）"""
    salt = secrets.token_hex(16)
    db().execute("UPDATE users SET recovery_hash=?, recovery_salt=?, recovery_created=? WHERE id=?",
                 (recovery_digest(salt, auth), salt, now(), uid))
    db().execute("INSERT INTO vault_keys(user_id,kind,cred_id,blob,created) VALUES(?,'recovery','',?,?) "
                 "ON CONFLICT(user_id,kind,cred_id) DO UPDATE SET blob=excluded.blob, created=excluded.created", (uid, blob, now()))


# ---------------------------------------------------------------- 作業証明（復旧の総当たり対策）

def pow_bits():
    """攻撃が増えるほど作業証明を難しくする（正規の利用者は1回だけなので負担は小さい）"""
    n = count_log("fail:recover", 60)
    return cfg().pow_bits + (5 if n >= 200 else 3 if n >= 50 else 0)


def pow_sign(text):
    return hmac.new(subkey("pow"), text.encode(), hashlib.sha256).hexdigest()[:32]


def pow_token():
    text = f"{secrets.token_hex(12)}.{epoch()}.{pow_bits()}"
    return f"{text}.{pow_sign(text)}", int(text.rsplit(".", 1)[1])


def pow_ok(token, nonce):
    if not isinstance(token, str) or not isinstance(nonce, (str, int)) or isinstance(nonce, bool) or len(str(nonce)) > 40:
        return False
    try:
        rnd, ts, bits, sig = token.split(".")
        bits, ts = int(bits), int(ts)
    except ValueError:
        return False
    text = f"{rnd}.{ts}.{bits}"
    if not hmac.compare_digest(sig, pow_sign(text)) or epoch() - ts > cfg().pow_ttl or bits < cfg().pow_bits:
        return False
    if int.from_bytes(hashlib.sha256(f"{token}:{nonce}".encode()).digest(), "big") >> (256 - bits) != 0:
        return False
    try:  # 同じ証明の使い回しを防ぐ
        db().execute("INSERT INTO pow_used(token, at) VALUES(?,?)", (token, epoch()))
    except sqlite3.IntegrityError:
        return False
    return True
