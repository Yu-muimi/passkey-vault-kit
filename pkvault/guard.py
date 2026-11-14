"""ログインの確かめ：接続元・ログイン中の人・ログインを保つ期間・記録・CSRF とホスト名の確認・使える人を決める印（デコレーター）"""
import base64
import ipaddress
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import g, jsonify, request, session

from .core import SAFE_METHODS, ago, cfg, db, epoch, msg, now


# ---------------------------------------------------------------- 接続元

def client_ip():
    h = cfg().client_ip_header
    return (request.headers.get(h) if h else None) or request.remote_addr or ""


def client_country():
    """接続元の国：前の中継が付ける2文字（JP など）。外部のサービスには問い合わせない"""
    h = cfg().country_header
    c = (request.headers.get(h) or "").strip().upper() if h else ""
    return c if re.fullmatch(r"[A-Z][A-Z0-9]", c) and c != "XX" else ""


def client_net():
    """回数制限の単位。IPv6 は1契約に /64 がまるごと割り当てられるので、/64 単位でまとめて数える"""
    ip = client_ip()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{ip}/64", strict=False)) if a.version == 6 else ip


# ---------------------------------------------------------------- ログインを保つ期間

def session_days_of(u):
    """その人が選んだ、ログインを保つ期間（日）。未設定・変な値は標準"""
    v = u["session_days"] if u is not None and "session_days" in u.keys() else None
    return v if v in cfg().session_days else cfg().session_days_default


def apply_session_days(days):
    """今のログイン（クッキー）を、選んだ期間に合わせる。毎回＝ブラウザーを閉じると消えるクッキー、それ以外＝その日数で消えるクッキー"""
    if session.get("scope") != "full":
        return
    if session.permanent != (days > 0):
        session.permanent = days > 0
    if session.get("ttl") != days:
        session["ttl"] = days


# ---------------------------------------------------------------- ログイン中の人

def in_recovery():
    return session.get("scope") == "recovery"


def account_block(u, withdrawing_ok=False):
    """ログインできない理由（なければ None）"""
    if u["banned"]:
        return msg("banned")
    if u["suspended_until"] and u["suspended_until"] > now():
        return msg("suspended", until=u["suspended_until"][:16].replace("T", " "))
    if u["delete_after"] and not withdrawing_ok:
        return msg("withdrawing", until=u["delete_after"][:10])
    return None


def current_user():
    """セッションの uid・sess_ver・端末が DB と一致し、期限内の場合だけログイン扱い"""
    if "pkv_user" in g:
        return g.pkv_user
    g.pkv_user = None
    uid = session.get("uid")
    if uid:
        c = cfg()
        u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        expired = in_recovery() and epoch() - session.get("auth_at", 0) > c.recovery_ttl
        expired = expired or epoch() - session.get("login_at", 0) > c.session_max_days * 86400
        # ログイン中の端末の一覧から外された端末は、ログインしていない扱い
        dev = db().execute("SELECT last_seen FROM devices WHERE id=? AND user_id=?", (session.get("dev") or "", uid)).fetchone() if u else None
        # 本人が選んだ期間より長く使っていない端末も、ログインしていない扱い（盗まれたクッキーが長く使われないように）
        if u and dev and session.get("scope") == "full":
            idle = timedelta(days=session_days_of(u) or c.every_time_idle_days)
            expired = expired or (dev["last_seen"] or "") < (datetime.now() - idle).isoformat(timespec="seconds")
        if u and dev and not expired and u["sess_ver"] == session.get("ver") and not account_block(u, withdrawing_ok=in_recovery()):
            g.pkv_user = dict(u)
            apply_session_days(session_days_of(u))  # クッキーの残り方も、選んだ期間に合わせる（ほかの端末で変えたときも）
            stale = ago(minutes=5)  # 最終アクセス（5分に1回だけ書く）
            if not u["last_seen"] or u["last_seen"] < stale or (dev["last_seen"] or "") < stale:
                db().execute("UPDATE users SET last_seen=? WHERE id=?", (now(), uid))
                db().execute("UPDATE devices SET last_seen=? WHERE id=?", (now(), session["dev"]))
                if request.method in SAFE_METHODS:
                    db().commit()  # 書く要求では、ここで確定しない（途中で書き込みの鍵を手放さず、要求の最後にまとめて確定する）
        else:
            session.clear()
    return g.pkv_user


def start_session(user, method, scope="full", cred="", cred_id=""):
    """ログインの記録（クッキー）を作り直し、この端末の割符を用意する"""
    session.clear()  # セッション固定攻撃を防ぐため、作り直す
    session.permanent = scope == "full"
    session["uid"] = user["id"]
    session["scope"] = scope
    apply_session_days(session_days_of(user))
    session["cid"] = cred_id
    dev = secrets.token_urlsafe(18)
    db().execute("INSERT INTO devices(id,user_id,share,ua,created,last_seen) VALUES(?,?,?,?,?,?)",
                 (dev, user["id"], base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
                  (request.headers.get("User-Agent") or "")[:200], now(), now()))
    session["dev"] = dev
    session["ver"] = user["sess_ver"]
    session["auth_at"] = session["login_at"] = epoch()
    session["method"] = method
    db().execute("UPDATE users SET last_login=?, last_seen=?, login_count=COALESCE(login_count,0)+1 WHERE id=?",
                 (now(), now(), user["id"]))
    log_event(user["id"], "login:" + method, cred)


def drop_devices(uid, keep=None):
    """端末の割符を消す（全端末のログアウト・退会・復旧のとき）。消した端末に置いたデータ鍵は開けなくなる"""
    db().execute("DELETE FROM devices WHERE user_id=? AND id<>?", (uid, keep or ""))


# ---------------------------------------------------------------- 記録・回数

def log_event(uid, event, cred="", detail=""):
    db().execute("INSERT INTO auth_log(user_id,event,ip,ua,at,cred,net,detail,country) VALUES(?,?,?,?,?,?,?,?,?)",
                 (uid, event, client_ip(), (request.headers.get("User-Agent") or "")[:200], now(), cred or "",
                  client_net(), (detail or "")[:1200], client_country()))


def count_log(event, since_minutes, net=None, cred=None):
    q, p = "SELECT COUNT(*) FROM auth_log WHERE event=? AND at>=?", [event, ago(minutes=since_minutes)]
    if net is not None:
        q += " AND net=?"
        p.append(net)
    if cred is not None:
        q += " AND cred=?"
        p.append(cred)
    return db().execute(q, p).fetchone()[0]


def note_limit(kind):
    """回数制限にかかったことを、その人の記録に残す（1分に1回まで）"""
    if not db().execute("SELECT 1 FROM auth_log WHERE user_id=? AND event=? AND at>=?", (g.uid, "limit:" + kind, ago(seconds=60))).fetchone():
        log_event(g.uid, "limit:" + kind)
        db().commit()


def fail(event, text, code=401, cred=""):
    log_event(None, event, cred)
    db().commit()
    return jsonify(error=text), code


def jstr(d, key, default=""):
    """JSON の値を文字として取り出す（数値・配列・null などが来ても落ちないように）"""
    v = d.get(key) if isinstance(d, dict) else None
    return v if isinstance(v, str) else default


def body():
    """JSON の本文（オブジェクトでなければ空。csrf_check で形は確かめ済み）"""
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


# ---------------------------------------------------------------- 要求ごとの確認（アプリ全体に掛ける）

def csrf_check():
    """部品の API とアプリの API（api_prefix の下）の変更系は、独自ヘッダー必須（他サイトのフォームや画像からは付けられない）。
    JSON の本文は必ずオブジェクト（配列・文字列・数値で落ちないように。分割送信でもすり抜けないよう、長さでは判定しない）"""
    c = cfg()
    if not request.path.startswith(c.api_prefix + "/") or request.method in SAFE_METHODS:
        return None
    if request.headers.get(c.csrf_header) != "1":
        return jsonify(error="bad request"), 400
    if request.is_json and not isinstance(request.get_json(silent=True), dict):
        return jsonify(error=msg("bad_format")), 400
    return None


def host_check():
    """本番（rp_id を決めたとき）は、それ以外の名前（Host ヘッダー）で来た要求を断る。中継を通らない直接の接続も断れる"""
    c = cfg()
    if c.require_ip_header and c.client_ip_header and not request.headers.get(c.client_ip_header):
        return "Not Found", 404
    if c.rp_id and request.host.split(":")[0].lower() != c.rp_id.lower():
        return "Not Found", 404
    return None


# ---------------------------------------------------------------- 使える人を決める印

def _guard(fn, recent=False, recovery_ok=False):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return jsonify(error="unauthorized"), 401
        # 復旧キーで入ったセッションは「新しいパスキーの登録」までしかできない（期限つき）
        if in_recovery() and (not recovery_ok or epoch() - session.get("auth_at", 0) > cfg().recovery_ttl):
            return jsonify(error="recovery", message=msg("recovery_only")), 403
        if recent and not in_recovery() and epoch() - session.get("auth_at", 0) > cfg().reauth_window:
            return jsonify(error="reauth", message=msg("reauth")), 403
        g.uid = u["id"]
        return fn(*a, **kw)
    return wrapper


def login_required(fn):
    """ログインしている本人だけ（g.uid に本人の番号が入る）"""
    return _guard(fn)


def recent_auth_required(fn):
    """直近（reauth_window 以内）にパスキーで本人確認していること。足りなければ 403 reauth（端末は本人確認してやり直す）"""
    return _guard(fn, recent=True)


def recovery_allowed(fn):
    """復旧モードのセッションでも使える（アカウント表示・パスキー登録など）。通常時は直近の本人確認が必要"""
    return _guard(fn, recent=True, recovery_ok=True)
